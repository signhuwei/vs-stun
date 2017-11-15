var Packet = require('./Packet');
var config = require('../config');

var resolve = exports.resolve = async function resolve ( socket, server, callback, retransmission={}) {
  let address = socket.address();
  let { count,timeout } = retransmission;
  let result = { 
    type: config.BLOCKED_UDP,
    local: { host: address.address, port: address.port },
    filtering :{ host: false, port: false },
    mapping : { host: false, port: false }
  };
  let v;
  try{
    v = await test.udp(socket, server, count, timeout);
  }catch(err){ }
  if ( !v || !v.other || !v.mapped ) return callback(null,result);
  
  result.public = v.mapped;
  result.type = config.OPEN_INTERNET;
  if ( test.compare(result.public, result.local) ) 
    return callback(null,result);
    
  result.type = config.FULL_CONE_NAT;
  if(!await test.filtering(socket, server, count, timeout))
    return callback(null,result);
  
  try{
    result.type = config.SYMMETRIC_NAT;
    v = await test.mapping(socket, v.other, count, timeout);
    if( !test.compare(v.mapped, result.public) )
      return callback(null,result);
  }catch(err){
    return callback(err);
  }

  result.type = config.RESTRICTED_CONE_NAT;
  if(!await test.portFiltering(socket,server,count,timeout))
    return callback(null,result);
  result.type = config.PORT_RESTRICTED_CONE_NAT;
  return callback(null,result);
}


var label = function label ( result ) {
  if ( !result.public ) result.type = config.BLOCKED_UDP;
  else {
    var mapping = result.mapping || { }
    var filtering = result.filtering || { }

    if ( test.compare(result.public, result.local) ) {
      if ( filtering.host || filtering.port ) {
        result.label = config.SYMMETRIC_FIREWALL;
      }
      else result.type = config.OPEN_INTERNET;
    }
    else {
      if ( mapping.host || mapping.port ) {
        result.type = config.SYMMETRIC_NAT;
      }
      else {
        if ( !filtering.host ) {
          result.type = config.FULL_CONE_NAT;
        }
        else if ( !filtering.port ) {
          result.type = config.RESTRICTED_CONE_NAT;
        }
        else result.type = config.PORT_RESTRICTED_CONE_NAT;
      }
    }
  }

  return result;
}


var test = function test ( ) { }

test.compare = function compare ( serverA, serverB ) {
  var serverA = serverA || { }
  var serverB = serverB || { }

  return serverA.host == serverB.host && serverA.port == serverB.port;
}

test.udp = test.mapping = test.portMapping = async ( ...conn )=>{
  var packet = new Packet();
  packet.type = Packet.BINDING_REQUEST;

  let value = await transmit(packet,...conn);
  
  var attribute = value.packet.doc.attribute;
  var other = attribute.otherAddress || attribute.changedAddress;
  var mapped = attribute.xorMappedAddress || attribute.mappedAddress;
  
  return { 
    other: other ? other.value.obj : null ,
    mapped: mapped ? mapped.value.obj : { } 
  };
}


test.filtering = async( ...conn )=>{
  var packet = new Packet();

  packet.type = Packet.BINDING_REQUEST;
  packet.append.changeRequest({ host: true, port: true });
  try{
    await transmit(packet,...conn);
    return false;
  }catch(err){
    return true;
  }
}

test.portFiltering = async ( ...conn )=>{
  var packet = new Packet();

  packet.type = Packet.BINDING_REQUEST;
  packet.append.changeRequest({ host: false, port: true });

  try{
    await transmit(packet,...conn);
    return false;
  }catch(err){
    return true;
  }
}

function transmit(packet,socket,server,count=config.RETRANSMISSION_COUNT,timeout=config.RETRANSMISSION_TIMEOUT){
  let _timer,_error,_errorHandle,_eventHandle;

  return new Promise((res,rej)=>{
    socket.on('error',_errorHandle = (err)=>{
      clearTimeout(_timer);
      _error = err;
      retry();
    });
    socket.on('message',_eventHandle = (data,info)=>{
      clearTimeout(_timer);
      socket.removeListener('message',_eventHandle);
      socket.removeListener('error',_errorHandle);

      var packet = Packet.parse(data);
      if(packet instanceof Error) return rej(packet);
      
      res({
        packet: Packet.parse(data),
        address: { host: info.address, port: info.port }
      });
    });

    function retry(){
      console.log(count);
      if(!--count) {
        socket.removeListener('message',_eventHandle);
        socket.removeListener('error',_errorHandle);
        rej(_error || new Error('request timeout'))
      }else{
        _timer = setTimeout(retry,timeout *= 2);
        console.log('send 2',server);
        socket.send(packet.raw,0,packet.raw.length,server.port,server.host);
      }
    }
    retry();
  });
}