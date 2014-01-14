var path = require('path');
var res = require('bindings')('scep.node');
var os = require('os');
var lib_path = path.dirname(res.path);
switch(os.platform()){
   case 'linux':
      lib_path += '/scep.so';
      break;
   case 'darwin': 
      lib_path += '/scep.dylib';
      break;
}
res.dlopen(lib_path);
delete res.dlopen;
delete res.path;
module.exports = res;
