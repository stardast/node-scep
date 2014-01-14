#include <dlfcn.h>

#include <node.h>
#include <node_buffer.h>

#include <stdio.h>
#include <stdlib.h>
#include <string>

using namespace v8;

int (*extract_csr)(unsigned char* p7_buf, size_t p7_len, char *cert, char *key,  char **data, size_t &length);
int (*encode_res)(unsigned char* cert_buf, size_t cert_len, unsigned char* p7_buf, size_t p7_len, char *cert, char *key, char **data, size_t &length );
int (*verify)(unsigned char* p7_buf, size_t p7_len, char **data, size_t &length );

Handle<Value> Extract_CSR(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
        ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
        return scope.Close(Undefined());
    }

    Local<Object> opt = args[0]->ToObject();
    if(!opt->IsObject()) {
      ThrowException(Exception::TypeError(String::New("Args[0] must be a buffer")));
      return scope.Close(Undefined());
    }

    Local<Value> req = opt->Get(v8::String::NewSymbol("req"));
    if(!req->IsObject() || !node::Buffer::HasInstance(req)) {
      ThrowException(Exception::TypeError(String::New("req must be a buffer")));
      return scope.Close(Undefined());
    }

    Local<Value> cert = opt->Get(v8::String::NewSymbol("cert"));
    Local<Value> key = opt->Get(v8::String::NewSymbol("key"));

    unsigned char*msg = (unsigned char*) node::Buffer::Data(req);
    size_t msglen = node::Buffer::Length(req);

    v8::String::Utf8Value s4(cert->ToString());
    v8::String::Utf8Value s5(key->ToString());

    char *data = NULL;
    size_t length = 0;

    extract_csr(msg, msglen, *s4, *s5, &data, length);

    return scope.Close(node::Buffer::New(data, length)->handle_);
}

Handle<Value> Encode_Res(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
        ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
        return scope.Close(Undefined());
    }

    Local<Object> opt = args[0]->ToObject();
    Local<Value> crt = opt->Get(v8::String::NewSymbol("crt"));
    Local<Value> p7 = opt->Get(v8::String::NewSymbol("req"));
    Local<Value> c = opt->Get(v8::String::NewSymbol("cert"));
    Local<Value> k = opt->Get(v8::String::NewSymbol("key"));
    v8::String::Utf8Value s1(c->ToString());
    v8::String::Utf8Value s2(k->ToString());

    unsigned char* crt_buf = (unsigned char*) node::Buffer::Data(crt);
    size_t crt_len = node::Buffer::Length(crt);

    unsigned char* p7_buf = (unsigned char*) node::Buffer::Data(p7);
    size_t p7_len = node::Buffer::Length(p7);

    char *data = NULL;
    size_t length = 0;

    encode_res(crt_buf, crt_len, p7_buf, p7_len, *s1, *s2, &data, length);

    return scope.Close(node::Buffer::New(data, length)->handle_);
}



Handle<Value> Verify_Response(const Arguments& args) {
  HandleScope scope;

    if (args.Length() < 1) {
        ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
        return scope.Close(Undefined());
    }
    Local<Value> a = args[0];
    if(!a->IsObject() || !node::Buffer::HasInstance(a)) {
      ThrowException(Exception::TypeError(String::New("Args[0] must be a buffer")));
      return scope.Close(Undefined());
    }

    Local<Object> opt = a->ToObject();

    unsigned char* p7_buf = (unsigned char*) node::Buffer::Data(opt);
    size_t p7_len = node::Buffer::Length(opt);

    char *data = NULL;
    size_t length = 0;
    verify(p7_buf, p7_len, &data, length);

    Local<Object> obj = Object::New();
//    obj->Set(String::NewSymbol("name"), String::New(X509_NAME_oneline(name, NULL, 0)));

    obj->Set(String::NewSymbol("out"), node::Buffer::New(data, length)->handle_);
    return scope.Close(obj);
}

#ifndef RTLD_DEEPBIND
#define RTLD_DEEPBIND   0 /* Mac no support  */
#endif

Handle<Value> DlOpen(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
        ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
        return scope.Close(Undefined());
    }
    Local<Value> a = args[0];
    if(!a->IsString()) {
      ThrowException(Exception::TypeError(String::New("Args[0] must be a string")));
      return scope.Close(Undefined());
    }

   v8::String::Utf8Value str(a->ToString());

   void* handle = dlopen(*str, RTLD_NOW | RTLD_DEEPBIND);
   if (!handle) {
       printf("ERROR\n");
   }
   void (*init)(void) = (void(*)(void)) dlsym(handle, "_init_lib");
   std::string n_v = "_verify";
   std::string n_ex = "_extract_csr";
   std::string n_en = "_encode_res";
   if(!init){
      init = (void(*)(void)) dlsym(handle, "init_lib");
      n_v = "verify";
      n_ex = "extract_csr";
      n_en = "encode_res";
   }
   init();
   
   verify = (int(*)(unsigned char* p7_buf, size_t p7_len, char **data, size_t &length)) dlsym(handle, n_v.c_str());
   extract_csr = (int(*)(unsigned char* p7_buf, size_t p7_len, char *cert, char *key,  char **data, size_t &length)) dlsym(handle, n_ex.c_str());
   encode_res = (int(*)(unsigned char* cert_buf, size_t cert_len, unsigned char* p7_buf, size_t p7_len, char *cert, char *key, char **data, size_t &length )) dlsym(handle, n_en.c_str());

   return scope.Close(Undefined());
}

void init(Handle<Object> exports) {
   exports->Set(String::NewSymbol("dlopen"), FunctionTemplate::New(DlOpen)->GetFunction());
   exports->Set(String::NewSymbol("extract_csr"), FunctionTemplate::New(Extract_CSR)->GetFunction());
   exports->Set(String::NewSymbol("encode_res"), FunctionTemplate::New(Encode_Res)->GetFunction());
   exports->Set(String::NewSymbol("verify_response"), FunctionTemplate::New(Verify_Response)->GetFunction());
}

NODE_MODULE(scep, init)
