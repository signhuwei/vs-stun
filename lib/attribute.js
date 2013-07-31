var ATTRIBUTE = {
  alternateServer   : require('./Attribute/alternateServer'),
  errorCode         : require('./Attribute/errorCode'),
  fingerprint       : require('./Attribute/fingerprint'),
  iceControlled     : require('./Attribute/iceControlled'),
  iceControlling    : require('./Attribute/iceControlling'),
  mappedAddress     : require('./Attribute/mappedAddress'),
  messageIntegrity  : require('./Attribute/messageIntegrity'),
  nonce             : require('./Attribute/nonce'),
  priority          : require('./Attribute/priority'),
  realm             : require('./Attribute/realm'),
  software          : require('./Attribute/software'),
  unknownAttributes : require('./Attribute/unknownAttributes'),
  useCandidate      : require('./Attribute/useCandidate'),
  username          : require('./Attribute/username'),
  xorMappedAddress  : require('./Attribute/xorMappedAddress')
}

var TYPE = { }

for ( var name in ATTRIBUTE ) TYPE[ATTRIBUTE[name].TYPE] = ATTRIBUTE[name];


var Attribute = module.exports = function Attribute ( name, obj, raw, pattern ) {
  var attribute = ATTRIBUTE[name], value = raw;
  var type = new Buffer(2), length = new Buffer(2);
  var pattern = new Buffer(pattern || '00', 'hex');
  var padding = new Buffer((4 - value.length % 4) % 4);

  type.writeUInt16BE(attribute.TYPE, 0);
  length.writeUInt16BE(value.length, 0);

  for ( var i = 0; i < padding.length; i += 1 ) {
    padding[i] = pattern[i % pattern.length];
  }

  this.name = name;
  this.raw = Buffer.concat([ type, length, value, padding ]);

  this.type    = { obj: attribute.TYPE,          raw: type }
  this.length  = { obj: value.length,            raw: length }
  this.value   = { obj: obj,                     raw: value }
  this.padding = { obj: padding.toString('hex'), raw: padding }
}

Attribute.prototype.toString = function toString ( ) {
  var string = [
    Attribute.typeToString(this),
    '=>',
    Attribute.paddingToString(this),
    '-',
    Attribute.lengthToString(this),
    '-',
    Attribute.valueToString(this)
  ];

  return string.join('     ');
}


Attribute.expand = function expand ( packet ) {
  for ( var name in ATTRIBUTE ) {
    Attribute.expand.attribute(packet, name);
  }
}

Attribute.expand.attribute = function expandAttribute ( packet, name ) {
  packet.append[name] = function append ( obj, pattern ) {
    var error = Attribute.expand.check(packet, name);
    if ( error ) return error;

    var raw = ATTRIBUTE[name].encode(packet, obj);
    if ( raw instanceof Error ) return raw;

    var obj = ATTRIBUTE[name].decode(packet, raw);
    if ( obj instanceof Error ) return obj;

    var pattern = new Buffer(pattern || '00', 'hex');
    var attribute = new Attribute(name, obj, raw, pattern);

    return packet.append(attribute);
  }
}

Attribute.expand.check = function expandCheck ( packet, name ) {
  if ( packet.doc.attribute.fingerprint ) {
    return new Error('fingerprint was the last attribute');
  }

  if ( packet.doc.attribute.messageIntegrity ) {
    if ( name != ATTRIBUTE.fingerprint.NAME ) {
      return new Error('only fingerprint can follow message integrity');
    }
  }

  switch ( name ) {
    case ATTRIBUTE.errorCode.NAME: {
      if ( !(packet.doc.type.obj & 0x0010) ) {
        return new Error('error code requires an error response packet type');
      }
    } break;
    case ATTRIBUTE.iceControlled.NAME: {
      if ( packet.doc.attribute.iceControlling ) {
        return new Error('ice controlling is already present');
      }
    } break;
    case ATTRIBUTE.iceControlling.NAME: {
      if ( packet.doc.attribute.iceControlled ) {
        return new Error('ice controlled is already present');
      }
    } break;
    case ATTRIBUTE.unknownAttributes.NAME: {
      if ( !packet.doc.attribute.errorCode ) {
        return new Error('error code must be present');
      }
      else if ( packet.doc.attribute.errorCode.obj != 420 ) {
        return new Error('unknown attributes require 420 error code');
      }
    } break;
  }
}

Attribute.parse = function parse ( packet, data ) {
  if ( !Attribute.parse.check(packet, data) ) {
    return new Error('invalid attribute');
  }

  var error, offset = packet.raw.length;

  var type = data.readUInt16BE(offset);
  var length = data.readUInt16BE(offset + 2);

  var begin = offset + 4 + length;
  var end = begin + (4 - length % 4) % 4;

  if ( !TYPE[type] ) return new Error('unknown attribute ' + type);
  if ( error = Attribute.expand.check(packet, TYPE[type].NAME) ) return error;

  var name = TYPE[type].NAME;
  var raw = data.slice(offset + 4, offset + 4 + length);
  var obj = ATTRIBUTE[name].decode(packet, raw);
  var pattern = data.toString('hex', begin, end);

  if ( obj instanceof Error ) return obj;

  return new Attribute(name, obj, raw, pattern);
}

Attribute.parse.check = function parseCheck ( packet, data ) {
  var offset = packet.raw.length;

  if ( data.length - offset < 4 ) return false;
  if ( (data.length - offset) % 4 != 0 ) return false;

  var length = data.readUInt16BE(offset + 2);

  return offset + 4 + length + (4 - length % 4) % 4 <= data.length;
}


Attribute.typeToString = function typeToString ( attribute ) {
  var type = '(0x' + attribute.type.raw.toString('hex') + ') ';

  switch ( attribute.type.obj ) {
    case ATTRIBUTE.alternateServer.TYPE   : return type + 'ALTERNATE SERVER    ';
    case ATTRIBUTE.errorCode.TYPE         : return type + 'ERROR CODE          ';
    case ATTRIBUTE.fingerprint.TYPE       : return type + 'FINGERPRINT         ';
    case ATTRIBUTE.iceControlled.TYPE     : return type + 'ICE CONTROLLED      ';
    case ATTRIBUTE.iceControlling.TYPE    : return type + 'ICE CONTROLLING     ';
    case ATTRIBUTE.mappedAddress.TYPE     : return type + 'MAPPED ADDRESS      ';
    case ATTRIBUTE.messageIntegrity.TYPE  : return type + 'MESSAGE INTEGRITY   ';
    case ATTRIBUTE.nonce.TYPE             : return type + 'NONCE               ';
    case ATTRIBUTE.priority.TYPE          : return type + 'PRIORITY            ';
    case ATTRIBUTE.realm.TYPE             : return type + 'REALM               ';
    case ATTRIBUTE.software.TYPE          : return type + 'SOFTWARE            ';
    case ATTRIBUTE.unknownAttributes.TYPE : return type + 'UNKNOWN ATTRIBUTES  ';
    case ATTRIBUTE.useCandidate.TYPE      : return type + 'USE CANDIDATE       ';
    case ATTRIBUTE.username.TYPE          : return type + 'USERNAME            ';
    case ATTRIBUTE.xorMappedAddress.TYPE  : return type + 'XOR MAPPED ADDRESS  ';
    default: return type + 'UNKNOWN ATTRIBUTE   ';
  }
}

Attribute.lengthToString = function lengthToString ( attribute ) {
  var info = 'VALUE LENGTH:';

  if ( attribute.length.obj < 10 ) return info + '   ' + attribute.length.obj;
  if ( attribute.length.obj < 100 ) return info + '  ' + attribute.length.obj;
  if ( attribute.length.obj < 1000 ) return info + ' ' + attribute.length.obj;

  return new Error('INVALID VALUE LENGTH'); 
}

Attribute.valueToString = function valueToString ( attribute ) {
  return 'VALUE: ' + JSON.stringify(attribute.value.obj);
}

Attribute.paddingToString = function paddingToString ( attribute ) {
  var info = 'PADDING:';

  if ( attribute.padding.raw.length == 0 ) return info + '       ';
  if ( attribute.padding.raw.length == 1 ) return info + '     ' + attribute.padding.obj;
  if ( attribute.padding.raw.length == 2 ) return info + '   ' + attribute.padding.obj;
  if ( attribute.padding.raw.length == 3 ) return info + ' ' + attribute.padding.obj;

  return new Error('INVALID PADDING LENGTH');
}