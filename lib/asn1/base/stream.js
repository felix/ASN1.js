var stream = require('stream');
var inherits = require('inherits');
var EncoderBuffer = require('../base').EncoderBuffer;

// Implement a readable stream, ie consumer can only read
function EncoderStream(options) {
  options = options || {}
  options.objectMode = true;
  if (!(this instanceof EncoderStream))
    return new EncoderStream(options);
  stream.Readable.call(this, options);

  // An array of data blocks to feed to consumer
  this.blocks = [];
}
inherits(EncoderStream, stream.Readable);
exports.EncoderStream = EncoderStream;

EncoderStream.prototype._read = function (size) {
  // Only send complete blocks?
  while (size) {
    if (this.blocks[0].length <= size) {
      var block = this.blocks.shift();
      this.push(block);
      size = size - block.length;
    } else {
      size = 0;
    }
  }
}

EncoderStream.prototype.send = function (value) {
  var block = {};
  if (Array.isArray(value)) {
    block.length = 0;
    block.value = value.map(function(item) {
      if (!(item instanceof EncoderBuffer))
        item = new EncoderBuffer(item, reporter);
      block.length += item.length;
      return item;
    }, block);
  } else if (typeof value === 'number') {
    if (!(0 <= value && value <= 0xff))
      return reporter.error('non-byte EncoderBuffer value');
    block.value = value;
    block.length = 1;
  } else if (typeof value === 'string') {
    block.value = value;
    block.length = Buffer.byteLength(value);
  } else if (Buffer.isBuffer(value)) {
    block.value = value;
    block.length = value.length;
  } else if (value instanceof EncoderBuffer) {
    block.value = value.join();
    block.length = block.value.length;
  } else {
    console.log('value is', value);
    new Error('Unsupported type: ' + typeof value);
  }

  // Turn the block into a buffer
  var buf = new Buffer(block.length);
  if (block.length === 0)
    return buf;

  if (Array.isArray(block.value)) {
    block.value.forEach(function(item) {
      item.join(buf, offset);
      offset += item.length;
    });
  } else {
    if (typeof block.value === 'number')
      buf[offset] = block.value;
    else if (typeof block.value === 'string')
      buf.write(block.value);
    else if (Buffer.isBuffer(block.value))
      block.value.copy(buf);
  }

  this.blocks.push(buf);
  console.log('blocks length', this.blocks.length);
}

EncoderStream.prototype._writev = function (chunks, callback) {
}

function DecoderStream(options) {
  if (!(this instanceof DecoderStream))
    return new DecoderStream(options);
  stream.Writable.call(this, options);
}
inherits(DecoderStream, stream.Writable);
exports.DecoderStream = DecoderStream;

DecoderStream.prototype._read = function (size) {
}

