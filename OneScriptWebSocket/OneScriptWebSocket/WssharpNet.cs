using System;
using System.Collections.Generic;
using System.Text;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Security.Principal;
using System.IO;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Collections;
using System.Runtime.Serialization;
using System.Security.Permissions;
using System.Net.Sockets;
using System.Threading;
using System.Runtime.InteropServices;
using System.ComponentModel;
using WebSocketSharp.Net.WebSockets;

namespace WebSocketSharp.Net
{
    internal class AuthenticationChallenge
    {
        private NameValueCollection _parameters;
        private AuthenticationSchemes _scheme;

        private AuthenticationChallenge(
          AuthenticationSchemes scheme,
          NameValueCollection parameters
        )
        {
            _scheme = scheme;
            _parameters = parameters;
        }

        internal AuthenticationChallenge(
          AuthenticationSchemes scheme,
          string realm
        )
          : this(scheme, new NameValueCollection())
        {
            _parameters["realm"] = realm;

            if (scheme == AuthenticationSchemes.Digest)
            {
                _parameters["nonce"] = CreateNonceValue();
                _parameters["algorithm"] = "MD5";
                _parameters["qop"] = "auth";
            }
        }

        internal NameValueCollection Parameters
        {
            get
            {
                return _parameters;
            }
        }

        public string Algorithm
        {
            get
            {
                return _parameters["algorithm"];
            }
        }

        public string Domain
        {
            get
            {
                return _parameters["domain"];
            }
        }

        public string Nonce
        {
            get
            {
                return _parameters["nonce"];
            }
        }

        public string Opaque
        {
            get
            {
                return _parameters["opaque"];
            }
        }

        public string Qop
        {
            get
            {
                return _parameters["qop"];
            }
        }

        public string Realm
        {
            get
            {
                return _parameters["realm"];
            }
        }

        public AuthenticationSchemes Scheme
        {
            get
            {
                return _scheme;
            }
        }

        public string Stale
        {
            get
            {
                return _parameters["stale"];
            }
        }

        internal static AuthenticationChallenge CreateBasicChallenge(string realm)
        {
            return new AuthenticationChallenge(AuthenticationSchemes.Basic, realm);
        }

        internal static AuthenticationChallenge CreateDigestChallenge(string realm)
        {
            return new AuthenticationChallenge(AuthenticationSchemes.Digest, realm);
        }

        internal static string CreateNonceValue()
        {
            var rand = new Random();
            var bytes = new byte[16];

            rand.NextBytes(bytes);

            var buff = new StringBuilder(32);

            foreach (var b in bytes)
                buff.Append(b.ToString("x2"));

            return buff.ToString();
        }

        internal static AuthenticationChallenge Parse(string value)
        {
            var chal = value.Split(new[] { ' ' }, 2);

            if (chal.Length != 2)
                return null;

            var schm = chal[0].ToLower();

            if (schm == "basic")
            {
                var parameters = ParseParameters(chal[1]);

                return new AuthenticationChallenge(
                         AuthenticationSchemes.Basic,
                         parameters
                       );
            }

            if (schm == "digest")
            {
                var parameters = ParseParameters(chal[1]);

                return new AuthenticationChallenge(
                         AuthenticationSchemes.Digest,
                         parameters
                       );
            }

            return null;
        }

        internal static NameValueCollection ParseParameters(string value)
        {
            var ret = new NameValueCollection();

            foreach (var param in value.SplitHeaderValue(','))
            {
                var i = param.IndexOf('=');

                var name = i > 0 ? param.Substring(0, i).Trim() : null;
                var val = i < 0
                          ? param.Trim().Trim('"')
                          : i < param.Length - 1
                            ? param.Substring(i + 1).Trim().Trim('"')
                            : String.Empty;

                ret.Add(name, val);
            }

            return ret;
        }

        internal string ToBasicString()
        {
            return String.Format("Basic realm=\"{0}\"", _parameters["realm"]);
        }

        internal string ToDigestString()
        {
            var buff = new StringBuilder(128);

            var domain = _parameters["domain"];
            var realm = _parameters["realm"];
            var nonce = _parameters["nonce"];

            if (domain != null)
            {
                buff.AppendFormat(
                  "Digest realm=\"{0}\", domain=\"{1}\", nonce=\"{2}\"",
                  realm,
                  domain,
                  nonce
                );
            }
            else
            {
                buff.AppendFormat("Digest realm=\"{0}\", nonce=\"{1}\"", realm, nonce);
            }

            var opaque = _parameters["opaque"];

            if (opaque != null)
                buff.AppendFormat(", opaque=\"{0}\"", opaque);

            var stale = _parameters["stale"];

            if (stale != null)
                buff.AppendFormat(", stale={0}", stale);

            var algo = _parameters["algorithm"];

            if (algo != null)
                buff.AppendFormat(", algorithm={0}", algo);

            var qop = _parameters["qop"];

            if (qop != null)
                buff.AppendFormat(", qop=\"{0}\"", qop);

            return buff.ToString();
        }

        public override string ToString()
        {
            if (_scheme == AuthenticationSchemes.Basic)
                return ToBasicString();

            if (_scheme == AuthenticationSchemes.Digest)
                return ToDigestString();

            return String.Empty;
        }
    }
    //=====================================================================================
    internal class AuthenticationResponse
    {
        private uint _nonceCount;
        private NameValueCollection _parameters;
        private AuthenticationSchemes _scheme;

        private AuthenticationResponse(
          AuthenticationSchemes scheme,
          NameValueCollection parameters
        )
        {
            _scheme = scheme;
            _parameters = parameters;
        }

        internal AuthenticationResponse(NetworkCredential credentials)
          : this(
              AuthenticationSchemes.Basic,
              new NameValueCollection(),
              credentials,
              0
            )
        {
        }

        internal AuthenticationResponse(
          AuthenticationChallenge challenge,
          NetworkCredential credentials,
          uint nonceCount
        )
          : this(challenge.Scheme, challenge.Parameters, credentials, nonceCount)
        {
        }

        internal AuthenticationResponse(
          AuthenticationSchemes scheme,
          NameValueCollection parameters,
          NetworkCredential credentials,
          uint nonceCount
        )
          : this(scheme, parameters)
        {
            _parameters["username"] = credentials.Username;
            _parameters["password"] = credentials.Password;
            _parameters["uri"] = credentials.Domain;
            _nonceCount = nonceCount;

            if (scheme == AuthenticationSchemes.Digest)
                initAsDigest();
        }

        internal uint NonceCount
        {
            get
            {
                return _nonceCount < UInt32.MaxValue ? _nonceCount : 0;
            }
        }

        internal NameValueCollection Parameters
        {
            get
            {
                return _parameters;
            }
        }

        public string Algorithm
        {
            get
            {
                return _parameters["algorithm"];
            }
        }

        public string Cnonce
        {
            get
            {
                return _parameters["cnonce"];
            }
        }

        public string Nc
        {
            get
            {
                return _parameters["nc"];
            }
        }

        public string Nonce
        {
            get
            {
                return _parameters["nonce"];
            }
        }

        public string Opaque
        {
            get
            {
                return _parameters["opaque"];
            }
        }

        public string Password
        {
            get
            {
                return _parameters["password"];
            }
        }

        public string Qop
        {
            get
            {
                return _parameters["qop"];
            }
        }

        public string Realm
        {
            get
            {
                return _parameters["realm"];
            }
        }

        public string Response
        {
            get
            {
                return _parameters["response"];
            }
        }

        public AuthenticationSchemes Scheme
        {
            get
            {
                return _scheme;
            }
        }

        public string Uri
        {
            get
            {
                return _parameters["uri"];
            }
        }

        public string UserName
        {
            get
            {
                return _parameters["username"];
            }
        }

        private static string createA1(
          string username,
          string password,
          string realm
        )
        {
            return String.Format("{0}:{1}:{2}", username, realm, password);
        }

        private static string createA1(
          string username,
          string password,
          string realm,
          string nonce,
          string cnonce
        )
        {
            var a1 = createA1(username, password, realm);

            return String.Format("{0}:{1}:{2}", hash(a1), nonce, cnonce);
        }

        private static string createA2(string method, string uri)
        {
            return String.Format("{0}:{1}", method, uri);
        }

        private static string createA2(string method, string uri, string entity)
        {
            return String.Format("{0}:{1}:{2}", method, uri, hash(entity));
        }

        private static string hash(string value)
        {
            var buff = new StringBuilder(64);

            var md5 = MD5.Create();
            var bytes = Encoding.UTF8.GetBytes(value);
            var res = md5.ComputeHash(bytes);

            foreach (var b in res)
                buff.Append(b.ToString("x2"));

            return buff.ToString();
        }

        private void initAsDigest()
        {
            var qops = _parameters["qop"];

            if (qops != null)
            {
                var hasAuth = qops.Split(',').Contains(
                                qop => qop.Trim().ToLower() == "auth"
                              );

                if (hasAuth)
                {
                    _parameters["qop"] = "auth";
                    _parameters["cnonce"] = AuthenticationChallenge.CreateNonceValue();
                    _parameters["nc"] = String.Format("{0:x8}", ++_nonceCount);
                }
                else
                {
                    _parameters["qop"] = null;
                }
            }

            _parameters["method"] = "GET";
            _parameters["response"] = CreateRequestDigest(_parameters);
        }

        internal static string CreateRequestDigest(NameValueCollection parameters)
        {
            var uname = parameters["username"];
            var passwd = parameters["password"];
            var realm = parameters["realm"];
            var nonce = parameters["nonce"];
            var uri = parameters["uri"];
            var algo = parameters["algorithm"];
            var qop = parameters["qop"];
            var cnonce = parameters["cnonce"];
            var nc = parameters["nc"];
            var method = parameters["method"];

            var a1 = algo != null && algo.ToLower() == "md5-sess"
                     ? createA1(uname, passwd, realm, nonce, cnonce)
                     : createA1(uname, passwd, realm);

            var a2 = qop != null && qop.ToLower() == "auth-int"
                     ? createA2(method, uri, parameters["entity"])
                     : createA2(method, uri);

            var secret = hash(a1);
            var data = qop != null
                       ? String.Format(
                           "{0}:{1}:{2}:{3}:{4}",
                           nonce,
                           nc,
                           cnonce,
                           qop,
                           hash(a2)
                         )
                       : String.Format("{0}:{1}", nonce, hash(a2));

            var keyed = String.Format("{0}:{1}", secret, data);

            return hash(keyed);
        }

        internal static AuthenticationResponse Parse(string value)
        {
            try
            {
                var cred = value.Split(new[] { ' ' }, 2);

                if (cred.Length != 2)
                    return null;

                var schm = cred[0].ToLower();

                if (schm == "basic")
                {
                    var parameters = ParseBasicCredentials(cred[1]);

                    return new AuthenticationResponse(
                             AuthenticationSchemes.Basic,
                             parameters
                           );
                }

                if (schm == "digest")
                {
                    var parameters = AuthenticationChallenge.ParseParameters(cred[1]);

                    return new AuthenticationResponse(
                             AuthenticationSchemes.Digest,
                             parameters
                           );
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

        internal static NameValueCollection ParseBasicCredentials(string value)
        {
            var ret = new NameValueCollection();

            // Decode the basic-credentials (a Base64 encoded string).

            var bytes = Convert.FromBase64String(value);
            var userPass = Encoding.UTF8.GetString(bytes);

            // The format is [<domain>\]<username>:<password>.

            var idx = userPass.IndexOf(':');
            var uname = userPass.Substring(0, idx);
            var passwd = idx < userPass.Length - 1
                         ? userPass.Substring(idx + 1)
                         : String.Empty;

            // Check if <domain> exists.

            idx = uname.IndexOf('\\');

            if (idx > -1)
                uname = uname.Substring(idx + 1);

            ret["username"] = uname;
            ret["password"] = passwd;

            return ret;
        }

        internal string ToBasicString()
        {
            var uname = _parameters["username"];
            var passwd = _parameters["password"];
            var userPass = String.Format("{0}:{1}", uname, passwd);

            var bytes = Encoding.UTF8.GetBytes(userPass);
            var cred = Convert.ToBase64String(bytes);

            return "Basic " + cred;
        }

        internal string ToDigestString()
        {
            var buff = new StringBuilder(256);

            var uname = _parameters["username"];
            var realm = _parameters["realm"];
            var nonce = _parameters["nonce"];
            var uri = _parameters["uri"];
            var res = _parameters["response"];

            buff.AppendFormat(
              "Digest username=\"{0}\", realm=\"{1}\", nonce=\"{2}\", uri=\"{3}\", response=\"{4}\"",
              uname,
              realm,
              nonce,
              uri,
              res
            );

            var opaque = _parameters["opaque"];

            if (opaque != null)
                buff.AppendFormat(", opaque=\"{0}\"", opaque);

            var algo = _parameters["algorithm"];

            if (algo != null)
                buff.AppendFormat(", algorithm={0}", algo);

            var qop = _parameters["qop"];

            if (qop != null)
            {
                var cnonce = _parameters["cnonce"];
                var nc = _parameters["nc"];

                buff.AppendFormat(
                  ", qop={0}, cnonce=\"{1}\", nc={2}",
                  qop,
                  cnonce,
                  nc
                );
            }

            return buff.ToString();
        }

        public IIdentity ToIdentity()
        {
            if (_scheme == AuthenticationSchemes.Basic)
            {
                var uname = _parameters["username"];
                var passwd = _parameters["password"];

                return new HttpBasicIdentity(uname, passwd);
            }

            if (_scheme == AuthenticationSchemes.Digest)
                return new HttpDigestIdentity(_parameters);

            return null;
        }

        public override string ToString()
        {
            if (_scheme == AuthenticationSchemes.Basic)
                return ToBasicString();

            if (_scheme == AuthenticationSchemes.Digest)
                return ToDigestString();

            return String.Empty;
        }
    }
    //=========================================================================================
    /// <summary>
    /// Specifies the scheme for authentication.
    /// </summary>
    public enum AuthenticationSchemes
    {
        /// <summary>
        /// No authentication is allowed.
        /// </summary>
        None,
        /// <summary>
        /// Specifies digest authentication.
        /// </summary>
        Digest = 1,
        /// <summary>
        /// Specifies basic authentication.
        /// </summary>
        Basic = 8,
        /// <summary>
        /// Specifies anonymous authentication.
        /// </summary>
        Anonymous = 0x8000
    }
    //=========================================================================================
    internal class Chunk
    {
        private byte[] _data;
        private int _offset;

        public Chunk(byte[] data)
        {
            _data = data;
        }

        public int ReadLeft
        {
            get
            {
                return _data.Length - _offset;
            }
        }

        public int Read(byte[] buffer, int offset, int count)
        {
            var left = _data.Length - _offset;

            if (left == 0)
                return 0;

            if (count > left)
                count = left;

            Buffer.BlockCopy(_data, _offset, buffer, offset, count);

            _offset += count;

            return count;
        }
    }
    //=====================================================================================
    internal class ChunkedRequestStream : RequestStream
    {
        private static readonly int _bufferLength;
        private HttpListenerContext _context;
        private ChunkStream _decoder;
        private bool _disposed;
        private bool _noMoreData;

        static ChunkedRequestStream()
        {
            _bufferLength = 8192;
        }

        internal ChunkedRequestStream(
          Stream innerStream,
          byte[] initialBuffer,
          int offset,
          int count,
          HttpListenerContext context
        )
          : base(innerStream, initialBuffer, offset, count, -1)
        {
            _context = context;

            _decoder = new ChunkStream(
                         (WebHeaderCollection)context.Request.Headers
                       );
        }

        internal bool HasRemainingBuffer
        {
            get
            {
                return _decoder.Count + Count > 0;
            }
        }

        internal byte[] RemainingBuffer
        {
            get
            {
                using (var buff = new MemoryStream())
                {
                    var cnt = _decoder.Count;

                    if (cnt > 0)
                        buff.Write(_decoder.EndBuffer, _decoder.Offset, cnt);

                    cnt = Count;

                    if (cnt > 0)
                        buff.Write(InitialBuffer, Offset, cnt);

                    buff.Close();

                    return buff.ToArray();
                }
            }
        }

        private void onRead(IAsyncResult asyncResult)
        {
            var rstate = (ReadBufferState)asyncResult.AsyncState;
            var ares = rstate.AsyncResult;

            try
            {
                var nread = base.EndRead(asyncResult);

                _decoder.Write(ares.Buffer, ares.Offset, nread);

                nread = _decoder.Read(rstate.Buffer, rstate.Offset, rstate.Count);

                rstate.Offset += nread;
                rstate.Count -= nread;

                if (rstate.Count == 0 || !_decoder.WantsMore || nread == 0)
                {
                    _noMoreData = !_decoder.WantsMore && nread == 0;

                    ares.Count = rstate.InitialCount - rstate.Count;

                    ares.Complete();

                    return;
                }

                base.BeginRead(ares.Buffer, ares.Offset, ares.Count, onRead, rstate);
            }
            catch (Exception ex)
            {
                _context.ErrorMessage = "I/O operation aborted";

                _context.SendError();

                ares.Complete(ex);
            }
        }

        public override IAsyncResult BeginRead(
          byte[] buffer,
          int offset,
          int count,
          AsyncCallback callback,
          object state
        )
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            if (buffer == null)
                throw new ArgumentNullException("buffer");

            if (offset < 0)
            {
                var msg = "A negative value.";

                throw new ArgumentOutOfRangeException("offset", msg);
            }

            if (count < 0)
            {
                var msg = "A negative value.";

                throw new ArgumentOutOfRangeException("count", msg);
            }

            var len = buffer.Length;

            if (offset + count > len)
            {
                var msg = "The sum of offset and count is greater than the length of buffer.";

                throw new ArgumentException(msg);
            }

            var ares = new HttpStreamAsyncResult(callback, state);

            if (_noMoreData)
            {
                ares.Complete();

                return ares;
            }

            var nread = _decoder.Read(buffer, offset, count);

            offset += nread;
            count -= nread;

            if (count == 0)
            {
                ares.Count = nread;

                ares.Complete();

                return ares;
            }

            if (!_decoder.WantsMore)
            {
                _noMoreData = nread == 0;

                ares.Count = nread;

                ares.Complete();

                return ares;
            }

            ares.Buffer = new byte[_bufferLength];
            ares.Offset = 0;
            ares.Count = _bufferLength;

            var rstate = new ReadBufferState(buffer, offset, count, ares);

            rstate.InitialCount += nread;

            base.BeginRead(ares.Buffer, ares.Offset, ares.Count, onRead, rstate);

            return ares;
        }

        public override void Close()
        {
            if (_disposed)
                return;

            base.Close();

            _disposed = true;
        }

        public override int EndRead(IAsyncResult asyncResult)
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            if (asyncResult == null)
                throw new ArgumentNullException("asyncResult");

            var ares = asyncResult as HttpStreamAsyncResult;

            if (ares == null)
            {
                var msg = "A wrong IAsyncResult instance.";

                throw new ArgumentException(msg, "asyncResult");
            }

            if (!ares.IsCompleted)
                ares.AsyncWaitHandle.WaitOne();

            if (ares.HasException)
            {
                var msg = "The I/O operation has been aborted.";

                throw new HttpListenerException(995, msg);
            }

            return ares.Count;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var ares = BeginRead(buffer, offset, count, null, null);

            return EndRead(ares);
        }
    }
    //===========================================================================
    internal class ChunkStream
    {
        private int _chunkRead;
        private int _chunkSize;
        private List<Chunk> _chunks;
        private int _count;
        private byte[] _endBuffer;
        private bool _gotIt;
        private WebHeaderCollection _headers;
        private int _offset;
        private StringBuilder _saved;
        private bool _sawCr;
        private InputChunkState _state;
        private int _trailerState;

        public ChunkStream(WebHeaderCollection headers)
        {
            _headers = headers;

            _chunkSize = -1;
            _chunks = new List<Chunk>();
            _saved = new StringBuilder();
        }

        internal int Count
        {
            get
            {
                return _count;
            }
        }

        internal byte[] EndBuffer
        {
            get
            {
                return _endBuffer;
            }
        }

        internal int Offset
        {
            get
            {
                return _offset;
            }
        }

        public WebHeaderCollection Headers
        {
            get
            {
                return _headers;
            }
        }

        public bool WantsMore
        {
            get
            {
                return _state < InputChunkState.End;
            }
        }

        private int read(byte[] buffer, int offset, int count)
        {
            var nread = 0;
            var cnt = _chunks.Count;

            for (var i = 0; i < cnt; i++)
            {
                var chunk = _chunks[i];

                if (chunk == null)
                    continue;

                if (chunk.ReadLeft == 0)
                {
                    _chunks[i] = null;

                    continue;
                }

                nread += chunk.Read(buffer, offset + nread, count - nread);

                if (nread == count)
                    break;
            }

            return nread;
        }

        private InputChunkState seekCrLf(byte[] buffer, ref int offset, int length)
        {
            if (!_sawCr)
            {
                if (buffer[offset++] != 13)
                    throwProtocolViolation("CR is expected.");

                _sawCr = true;

                if (offset == length)
                    return InputChunkState.DataEnded;
            }

            if (buffer[offset++] != 10)
                throwProtocolViolation("LF is expected.");

            return InputChunkState.None;
        }

        private InputChunkState setChunkSize(
          byte[] buffer,
          ref int offset,
          int length
        )
        {
            byte b = 0;

            while (offset < length)
            {
                b = buffer[offset++];

                if (_sawCr)
                {
                    if (b != 10)
                        throwProtocolViolation("LF is expected.");

                    break;
                }

                if (b == 13)
                {
                    _sawCr = true;

                    continue;
                }

                if (b == 10)
                    throwProtocolViolation("LF is unexpected.");

                if (_gotIt)
                    continue;

                if (b == 32 || b == 59)
                { // SP or ';'
                    _gotIt = true;

                    continue;
                }

                _saved.Append((char)b);
            }

            if (_saved.Length > 20)
                throwProtocolViolation("The chunk size is too big.");

            if (b != 10)
                return InputChunkState.None;

            var s = _saved.ToString();

            try
            {
                _chunkSize = Int32.Parse(s, NumberStyles.HexNumber);
            }
            catch
            {
                throwProtocolViolation("The chunk size cannot be parsed.");
            }

            _chunkRead = 0;

            if (_chunkSize == 0)
            {
                _trailerState = 2;

                return InputChunkState.Trailer;
            }

            return InputChunkState.Data;
        }

        private InputChunkState setTrailer(
          byte[] buffer,
          ref int offset,
          int length
        )
        {
            while (offset < length)
            {
                if (_trailerState == 4) // CR LF CR LF
                    break;

                var b = buffer[offset++];

                _saved.Append((char)b);

                if (_trailerState == 1 || _trailerState == 3)
                { // CR or CR LF CR
                    if (b != 10)
                        throwProtocolViolation("LF is expected.");

                    _trailerState++;

                    continue;
                }

                if (b == 13)
                {
                    _trailerState++;

                    continue;
                }

                if (b == 10)
                    throwProtocolViolation("LF is unexpected.");

                _trailerState = 0;
            }

            var len = _saved.Length;

            if (len > 4196)
                throwProtocolViolation("The trailer is too long.");

            if (_trailerState < 4)
                return InputChunkState.Trailer;

            if (len == 2)
                return InputChunkState.End;

            _saved.Length = len - 2;

            var val = _saved.ToString();
            var reader = new StringReader(val);

            while (true)
            {
                var line = reader.ReadLine();

                if (line == null || line.Length == 0)
                    break;

                _headers.Add(line);
            }

            return InputChunkState.End;
        }

        private static void throwProtocolViolation(string message)
        {
            throw new WebException(
                    message,
                    null,
                    WebExceptionStatus.ServerProtocolViolation,
                    null
                  );
        }

        private void write(byte[] buffer, int offset, int length)
        {
            if (_state == InputChunkState.End)
                throwProtocolViolation("The chunks were ended.");

            if (_state == InputChunkState.None)
            {
                _state = setChunkSize(buffer, ref offset, length);

                if (_state == InputChunkState.None)
                    return;

                _saved.Length = 0;
                _sawCr = false;
                _gotIt = false;
            }

            if (_state == InputChunkState.Data)
            {
                if (offset >= length)
                    return;

                _state = writeData(buffer, ref offset, length);

                if (_state == InputChunkState.Data)
                    return;
            }

            if (_state == InputChunkState.DataEnded)
            {
                if (offset >= length)
                    return;

                _state = seekCrLf(buffer, ref offset, length);

                if (_state == InputChunkState.DataEnded)
                    return;

                _sawCr = false;
            }

            if (_state == InputChunkState.Trailer)
            {
                if (offset >= length)
                    return;

                _state = setTrailer(buffer, ref offset, length);

                if (_state == InputChunkState.Trailer)
                    return;

                _saved.Length = 0;
            }

            if (_state == InputChunkState.End)
            {
                _endBuffer = buffer;
                _offset = offset;
                _count = length - offset;

                return;
            }

            if (offset >= length)
                return;

            write(buffer, offset, length);
        }

        private InputChunkState writeData(
          byte[] buffer,
          ref int offset,
          int length
        )
        {
            var cnt = length - offset;
            var left = _chunkSize - _chunkRead;

            if (cnt > left)
                cnt = left;

            var data = new byte[cnt];

            Buffer.BlockCopy(buffer, offset, data, 0, cnt);

            var chunk = new Chunk(data);

            _chunks.Add(chunk);

            offset += cnt;
            _chunkRead += cnt;

            return _chunkRead == _chunkSize
                   ? InputChunkState.DataEnded
                   : InputChunkState.Data;
        }

        internal void ResetChunkStore()
        {
            _chunkRead = 0;
            _chunkSize = -1;

            _chunks.Clear();
        }

        public int Read(byte[] buffer, int offset, int count)
        {
            if (count <= 0)
                return 0;

            return read(buffer, offset, count);
        }

        public void Write(byte[] buffer, int offset, int count)
        {
            if (count <= 0)
                return;

            write(buffer, offset, offset + count);
        }
    }
    //==============================================================================
    /// <summary>
    /// Stores the parameters for an <see cref="SslStream"/> instance used by
    /// a client.
    /// </summary>
    public class ClientSslConfiguration
    {
        private bool _checkCertRevocation;
        private LocalCertificateSelectionCallback _clientCertSelectionCallback;
        private X509CertificateCollection _clientCerts;
        private SslProtocols _enabledSslProtocols;
        private RemoteCertificateValidationCallback _serverCertValidationCallback;
        private string _targetHost;

        /// <summary>
        /// Initializes a new instance of the <see cref="ClientSslConfiguration"/>
        /// class with the specified target host name.
        /// </summary>
        /// <param name="targetHost">
        /// A <see cref="string"/> that specifies the name of the server that
        /// will share a secure connection with the client.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="targetHost"/> is an empty string.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="targetHost"/> is <see langword="null"/>.
        /// </exception>
        public ClientSslConfiguration(string targetHost)
        {
            if (targetHost == null)
                throw new ArgumentNullException("targetHost");

            if (targetHost.Length == 0)
                throw new ArgumentException("An empty string.", "targetHost");

            _targetHost = targetHost;

            _enabledSslProtocols = SslProtocols.None;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ClientSslConfiguration"/>
        /// class copying from the specified configuration.
        /// </summary>
        /// <param name="configuration">
        /// A <see cref="ClientSslConfiguration"/> from which to copy.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="configuration"/> is <see langword="null"/>.
        /// </exception>
        public ClientSslConfiguration(ClientSslConfiguration configuration)
        {
            if (configuration == null)
                throw new ArgumentNullException("configuration");

            _checkCertRevocation = configuration._checkCertRevocation;
            _clientCertSelectionCallback = configuration._clientCertSelectionCallback;
            _clientCerts = configuration._clientCerts;
            _enabledSslProtocols = configuration._enabledSslProtocols;
            _serverCertValidationCallback = configuration._serverCertValidationCallback;
            _targetHost = configuration._targetHost;
        }

        /// <summary>
        /// Gets or sets a value indicating whether the certificate revocation
        /// list is checked during authentication.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the certificate revocation list is checked during
        ///   authentication; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool CheckCertificateRevocation
        {
            get
            {
                return _checkCertRevocation;
            }

            set
            {
                _checkCertRevocation = value;
            }
        }

        /// <summary>
        /// Gets or sets the collection of the certificates from which to select
        /// one to supply to the server.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="X509CertificateCollection"/> that contains
        ///   the certificates from which to select.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not present.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        public X509CertificateCollection ClientCertificates
        {
            get
            {
                return _clientCerts;
            }

            set
            {
                _clientCerts = value;
            }
        }

        /// <summary>
        /// Gets or sets the callback used to select the certificate to supply to
        /// the server.
        /// </summary>
        /// <remarks>
        /// No certificate is supplied if the callback returns <see langword="null"/>.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="LocalCertificateSelectionCallback"/> delegate.
        ///   </para>
        ///   <para>
        ///   It represents the delegate called when the client selects
        ///   the certificate.
        ///   </para>
        ///   <para>
        ///   The default value invokes a method that only returns
        ///   <see langword="null"/>.
        ///   </para>
        /// </value>
        public LocalCertificateSelectionCallback ClientCertificateSelectionCallback
        {
            get
            {
                if (_clientCertSelectionCallback == null)
                    _clientCertSelectionCallback = defaultSelectClientCertificate;

                return _clientCertSelectionCallback;
            }

            set
            {
                _clientCertSelectionCallback = value;
            }
        }

        /// <summary>
        /// Gets or sets the enabled versions of the SSL/TLS protocols.
        /// </summary>
        /// <value>
        ///   <para>
        ///   Any of the <see cref="SslProtocols"/> enum values.
        ///   </para>
        ///   <para>
        ///   It represents the enabled versions of the SSL/TLS protocols.
        ///   </para>
        ///   <para>
        ///   The default value is <see cref="SslProtocols.None"/>.
        ///   </para>
        /// </value>
        public SslProtocols EnabledSslProtocols
        {
            get
            {
                return _enabledSslProtocols;
            }

            set
            {
                _enabledSslProtocols = value;
            }
        }

        /// <summary>
        /// Gets or sets the callback used to validate the certificate supplied by
        /// the server.
        /// </summary>
        /// <remarks>
        /// The certificate is valid if the callback returns <c>true</c>.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="RemoteCertificateValidationCallback"/> delegate.
        ///   </para>
        ///   <para>
        ///   It represents the delegate called when the client validates
        ///   the certificate.
        ///   </para>
        ///   <para>
        ///   The default value invokes a method that only returns <c>true</c>.
        ///   </para>
        /// </value>
        public RemoteCertificateValidationCallback ServerCertificateValidationCallback
        {
            get
            {
                if (_serverCertValidationCallback == null)
                    _serverCertValidationCallback = defaultValidateServerCertificate;

                return _serverCertValidationCallback;
            }

            set
            {
                _serverCertValidationCallback = value;
            }
        }

        /// <summary>
        /// Gets or sets the target host name.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the name of the server that
        /// will share a secure connection with the client.
        /// </value>
        /// <exception cref="ArgumentException">
        /// The value specified for a set operation is an empty string.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// The value specified for a set operation is <see langword="null"/>.
        /// </exception>
        public string TargetHost
        {
            get
            {
                return _targetHost;
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                if (value.Length == 0)
                    throw new ArgumentException("An empty string.", "value");

                _targetHost = value;
            }
        }

        private static X509Certificate defaultSelectClientCertificate(
          object sender,
          string targetHost,
          X509CertificateCollection clientCertificates,
          X509Certificate serverCertificate,
          string[] acceptableIssuers
        )
        {
            return null;
        }

        private static bool defaultValidateServerCertificate(
          object sender,
          X509Certificate certificate,
          X509Chain chain,
          SslPolicyErrors sslPolicyErrors
        )
        {
            return true;
        }
    }
    //================================================================================
    /// <summary>
    /// Provides a set of methods and properties used to manage an HTTP cookie.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///   This class refers to the following specifications:
    ///   </para>
    ///   <list type="bullet">
    ///     <item>
    ///       <term>
    ///       <see href="http://web.archive.org/web/20020803110822/http://wp.netscape.com/newsref/std/cookie_spec.html">
    ///       Netscape specification</see>
    ///       </term>
    ///     </item>
    ///     <item>
    ///       <term>
    ///       <see href="https://tools.ietf.org/html/rfc2109">RFC 2109</see>
    ///       </term>
    ///     </item>
    ///     <item>
    ///       <term>
    ///       <see href="https://tools.ietf.org/html/rfc2965">RFC 2965</see>
    ///       </term>
    ///     </item>
    ///     <item>
    ///       <term>
    ///       <see href="https://tools.ietf.org/html/rfc6265">RFC 6265</see>
    ///       </term>
    ///     </item>
    ///   </list>
    ///   <para>
    ///   This class cannot be inherited.
    ///   </para>
    /// </remarks>
    [Serializable]
    public sealed class Cookie
    {
        private string _comment;
        private Uri _commentUri;
        private bool _discard;
        private string _domain;
        private static readonly int[] _emptyPorts;
        private DateTime _expires;
        private bool _httpOnly;
        private string _name;
        private string _path;
        private string _port;
        private int[] _ports;
        private static readonly char[] _reservedCharsForValue;
        private string _sameSite;
        private bool _secure;
        private DateTime _timeStamp;
        private string _value;
        private int _version;

        static Cookie()
        {
            _emptyPorts = new int[0];
            _reservedCharsForValue = new[] { ';', ',' };
        }

        internal Cookie()
        {
            init(String.Empty, String.Empty, String.Empty, String.Empty);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Cookie"/> class with
        /// the specified name and value.
        /// </summary>
        /// <param name="name">
        ///   <para>
        ///   A <see cref="string"/> that specifies the name of the cookie.
        ///   </para>
        ///   <para>
        ///   The name must be a token defined in
        ///   <see href="http://tools.ietf.org/html/rfc2616#section-2.2">
        ///   RFC 2616</see>.
        ///   </para>
        /// </param>
        /// <param name="value">
        /// A <see cref="string"/> that specifies the value of the cookie.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="name"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> starts with a dollar sign.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="value"/> is a string not enclosed in double quotes
        ///   although it contains a reserved character.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="name"/> is <see langword="null"/>.
        /// </exception>
        public Cookie(string name, string value)
          : this(name, value, String.Empty, String.Empty)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Cookie"/> class with
        /// the specified name, value, and path.
        /// </summary>
        /// <param name="name">
        ///   <para>
        ///   A <see cref="string"/> that specifies the name of the cookie.
        ///   </para>
        ///   <para>
        ///   The name must be a token defined in
        ///   <see href="http://tools.ietf.org/html/rfc2616#section-2.2">
        ///   RFC 2616</see>.
        ///   </para>
        /// </param>
        /// <param name="value">
        /// A <see cref="string"/> that specifies the value of the cookie.
        /// </param>
        /// <param name="path">
        /// A <see cref="string"/> that specifies the value of the Path
        /// attribute of the cookie.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="name"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> starts with a dollar sign.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="value"/> is a string not enclosed in double quotes
        ///   although it contains a reserved character.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="name"/> is <see langword="null"/>.
        /// </exception>
        public Cookie(string name, string value, string path)
          : this(name, value, path, String.Empty)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Cookie"/> class with
        /// the specified name, value, path, and domain.
        /// </summary>
        /// <param name="name">
        ///   <para>
        ///   A <see cref="string"/> that specifies the name of the cookie.
        ///   </para>
        ///   <para>
        ///   The name must be a token defined in
        ///   <see href="http://tools.ietf.org/html/rfc2616#section-2.2">
        ///   RFC 2616</see>.
        ///   </para>
        /// </param>
        /// <param name="value">
        /// A <see cref="string"/> that specifies the value of the cookie.
        /// </param>
        /// <param name="path">
        /// A <see cref="string"/> that specifies the value of the Path
        /// attribute of the cookie.
        /// </param>
        /// <param name="domain">
        /// A <see cref="string"/> that specifies the value of the Domain
        /// attribute of the cookie.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="name"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> starts with a dollar sign.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="value"/> is a string not enclosed in double quotes
        ///   although it contains a reserved character.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="name"/> is <see langword="null"/>.
        /// </exception>
        public Cookie(string name, string value, string path, string domain)
        {
            if (name == null)
                throw new ArgumentNullException("name");

            if (name.Length == 0)
                throw new ArgumentException("An empty string.", "name");

            if (name[0] == '$')
            {
                var msg = "It starts with a dollar sign.";

                throw new ArgumentException(msg, "name");
            }

            if (!name.IsToken())
            {
                var msg = "It contains an invalid character.";

                throw new ArgumentException(msg, "name");
            }

            if (value == null)
                value = String.Empty;

            if (value.Contains(_reservedCharsForValue))
            {
                if (!value.IsEnclosedIn('"'))
                {
                    var msg = "A string not enclosed in double quotes.";

                    throw new ArgumentException(msg, "value");
                }
            }

            init(name, value, path ?? String.Empty, domain ?? String.Empty);
        }

        internal bool ExactDomain
        {
            get
            {
                return _domain.Length == 0 || _domain[0] != '.';
            }
        }

        internal int MaxAge
        {
            get
            {
                if (_expires == DateTime.MinValue)
                    return 0;

                var expires = _expires.Kind != DateTimeKind.Local
                              ? _expires.ToLocalTime()
                              : _expires;

                var span = expires - DateTime.Now;

                return span > TimeSpan.Zero
                       ? (int)span.TotalSeconds
                       : 0;
            }

            set
            {
                _expires = value > 0
                           ? DateTime.Now.AddSeconds((double)value)
                           : DateTime.Now;
            }
        }

        internal int[] Ports
        {
            get
            {
                return _ports ?? _emptyPorts;
            }
        }

        internal string SameSite
        {
            get
            {
                return _sameSite;
            }

            set
            {
                _sameSite = value;
            }
        }

        /// <summary>
        /// Gets the value of the Comment attribute of the cookie.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the comment to document
        ///   intended use of the cookie.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not present.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        public string Comment
        {
            get
            {
                return _comment;
            }

            internal set
            {
                _comment = value;
            }
        }

        /// <summary>
        /// Gets the value of the CommentURL attribute of the cookie.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="Uri"/> that represents the URI that provides
        ///   the comment to document intended use of the cookie.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not present.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        public Uri CommentUri
        {
            get
            {
                return _commentUri;
            }

            internal set
            {
                _commentUri = value;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the client discards the cookie
        /// unconditionally when the client terminates.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the client discards the cookie unconditionally
        ///   when the client terminates; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool Discard
        {
            get
            {
                return _discard;
            }

            internal set
            {
                _discard = value;
            }
        }

        /// <summary>
        /// Gets or sets the value of the Domain attribute of the cookie.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the domain name that
        ///   the cookie is valid for.
        ///   </para>
        ///   <para>
        ///   An empty string if not necessary.
        ///   </para>
        /// </value>
        public string Domain
        {
            get
            {
                return _domain;
            }

            set
            {
                _domain = value ?? String.Empty;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the cookie has expired.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the cookie has expired; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool Expired
        {
            get
            {
                return _expires != DateTime.MinValue && _expires <= DateTime.Now;
            }

            set
            {
                _expires = value ? DateTime.Now : DateTime.MinValue;
            }
        }

        /// <summary>
        /// Gets or sets the value of the Expires attribute of the cookie.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="DateTime"/> that represents the date and time that
        ///   the cookie expires on.
        ///   </para>
        ///   <para>
        ///   <see cref="DateTime.MinValue"/> if not necessary.
        ///   </para>
        ///   <para>
        ///   The default value is <see cref="DateTime.MinValue"/>.
        ///   </para>
        /// </value>
        public DateTime Expires
        {
            get
            {
                return _expires;
            }

            set
            {
                _expires = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether non-HTTP APIs can access
        /// the cookie.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if non-HTTP APIs cannot access the cookie; otherwise,
        ///   <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool HttpOnly
        {
            get
            {
                return _httpOnly;
            }

            set
            {
                _httpOnly = value;
            }
        }

        /// <summary>
        /// Gets or sets the name of the cookie.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the name of the cookie.
        ///   </para>
        ///   <para>
        ///   The name must be a token defined in
        ///   <see href="http://tools.ietf.org/html/rfc2616#section-2.2">
        ///   RFC 2616</see>.
        ///   </para>
        /// </value>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   The value specified for a set operation is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The value specified for a set operation starts with a dollar sign.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The value specified for a set operation contains an invalid character.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// The value specified for a set operation is <see langword="null"/>.
        /// </exception>
        public string Name
        {
            get
            {
                return _name;
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                if (value.Length == 0)
                    throw new ArgumentException("An empty string.", "value");

                if (value[0] == '$')
                {
                    var msg = "It starts with a dollar sign.";

                    throw new ArgumentException(msg, "value");
                }

                if (!value.IsToken())
                {
                    var msg = "It contains an invalid character.";

                    throw new ArgumentException(msg, "value");
                }

                _name = value;
            }
        }

        /// <summary>
        /// Gets or sets the value of the Path attribute of the cookie.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the subset of URI on
        /// the origin server that the cookie applies to.
        /// </value>
        public string Path
        {
            get
            {
                return _path;
            }

            set
            {
                _path = value ?? String.Empty;
            }
        }

        /// <summary>
        /// Gets the value of the Port attribute of the cookie.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the list of TCP ports
        ///   that the cookie applies to.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not present.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        public string Port
        {
            get
            {
                return _port;
            }

            internal set
            {
                int[] ports;

                if (!tryCreatePorts(value, out ports))
                    return;

                _ports = ports;
                _port = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the security level of
        /// the cookie is secure.
        /// </summary>
        /// <remarks>
        /// When this property is <c>true</c>, the cookie may be included in
        /// the request only if the request is transmitted over HTTPS.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the security level of the cookie is secure;
        ///   otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool Secure
        {
            get
            {
                return _secure;
            }

            set
            {
                _secure = value;
            }
        }

        /// <summary>
        /// Gets the time when the cookie was issued.
        /// </summary>
        /// <value>
        /// A <see cref="DateTime"/> that represents the time when
        /// the cookie was issued.
        /// </value>
        public DateTime TimeStamp
        {
            get
            {
                return _timeStamp;
            }
        }

        /// <summary>
        /// Gets or sets the value of the cookie.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the value of the cookie.
        /// </value>
        /// <exception cref="ArgumentException">
        /// The value specified for a set operation is a string not enclosed in
        /// double quotes although it contains a reserved character.
        /// </exception>
        public string Value
        {
            get
            {
                return _value;
            }

            set
            {
                if (value == null)
                    value = String.Empty;

                if (value.Contains(_reservedCharsForValue))
                {
                    if (!value.IsEnclosedIn('"'))
                    {
                        var msg = "A string not enclosed in double quotes.";

                        throw new ArgumentException(msg, "value");
                    }
                }

                _value = value;
            }
        }

        /// <summary>
        /// Gets the value of the Version attribute of the cookie.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An <see cref="int"/> that represents the version of HTTP state
        ///   management that the cookie conforms to.
        ///   </para>
        ///   <para>
        ///   0 or 1.
        ///   </para>
        ///   <para>
        ///   0 if not present.
        ///   </para>
        ///   <para>
        ///   The default value is 0.
        ///   </para>
        /// </value>
        public int Version
        {
            get
            {
                return _version;
            }

            internal set
            {
                if (value < 0 || value > 1)
                    return;

                _version = value;
            }
        }

        private static int hash(int i, int j, int k, int l, int m)
        {
            return i
                   ^ (j << 13 | j >> 19)
                   ^ (k << 26 | k >> 6)
                   ^ (l << 7 | l >> 25)
                   ^ (m << 20 | m >> 12);
        }

        private void init(string name, string value, string path, string domain)
        {
            _name = name;
            _value = value;
            _path = path;
            _domain = domain;

            _expires = DateTime.MinValue;
            _timeStamp = DateTime.Now;
        }

        private string toResponseStringVersion0()
        {
            var buff = new StringBuilder(64);

            buff.AppendFormat("{0}={1}", _name, _value);

            if (_expires != DateTime.MinValue)
            {
                var expires = _expires
                              .ToUniversalTime()
                              .ToString(
                                "ddd, dd'-'MMM'-'yyyy HH':'mm':'ss 'GMT'",
                                CultureInfo.CreateSpecificCulture("en-US")
                              );

                buff.AppendFormat("; Expires={0}", expires);
            }

            if (!_path.IsNullOrEmpty())
                buff.AppendFormat("; Path={0}", _path);

            if (!_domain.IsNullOrEmpty())
                buff.AppendFormat("; Domain={0}", _domain);

            if (!_sameSite.IsNullOrEmpty())
                buff.AppendFormat("; SameSite={0}", _sameSite);

            if (_secure)
                buff.Append("; Secure");

            if (_httpOnly)
                buff.Append("; HttpOnly");

            return buff.ToString();
        }

        private string toResponseStringVersion1()
        {
            var buff = new StringBuilder(64);

            buff.AppendFormat("{0}={1}; Version={2}", _name, _value, _version);

            if (_expires != DateTime.MinValue)
                buff.AppendFormat("; Max-Age={0}", MaxAge);

            if (!_path.IsNullOrEmpty())
                buff.AppendFormat("; Path={0}", _path);

            if (!_domain.IsNullOrEmpty())
                buff.AppendFormat("; Domain={0}", _domain);

            if (_port != null)
            {
                if (_port != "\"\"")
                    buff.AppendFormat("; Port={0}", _port);
                else
                    buff.Append("; Port");
            }

            if (_comment != null)
            {
                var comment = HttpUtility.UrlEncode(_comment);

                buff.AppendFormat("; Comment={0}", comment);
            }

            if (_commentUri != null)
            {
                var url = _commentUri.OriginalString;

                buff.AppendFormat(
                  "; CommentURL={0}",
                  !url.IsToken() ? url.Quote() : url
                );
            }

            if (_discard)
                buff.Append("; Discard");

            if (_secure)
                buff.Append("; Secure");

            return buff.ToString();
        }

        private static bool tryCreatePorts(string value, out int[] result)
        {
            result = null;

            var arr = value.Trim('"').Split(',');
            var len = arr.Length;
            var res = new int[len];

            for (var i = 0; i < len; i++)
            {
                var s = arr[i].Trim();

                if (s.Length == 0)
                {
                    res[i] = Int32.MinValue;

                    continue;
                }

                if (!Int32.TryParse(s, out res[i]))
                    return false;
            }

            result = res;

            return true;
        }

        internal bool EqualsWithoutValue(Cookie cookie)
        {
            var caseSensitive = StringComparison.InvariantCulture;
            var caseInsensitive = StringComparison.InvariantCultureIgnoreCase;

            return _name.Equals(cookie._name, caseInsensitive)
                   && _path.Equals(cookie._path, caseSensitive)
                   && _domain.Equals(cookie._domain, caseInsensitive)
                   && _version == cookie._version;
        }

        internal bool EqualsWithoutValueAndVersion(Cookie cookie)
        {
            var caseSensitive = StringComparison.InvariantCulture;
            var caseInsensitive = StringComparison.InvariantCultureIgnoreCase;

            return _name.Equals(cookie._name, caseInsensitive)
                   && _path.Equals(cookie._path, caseSensitive)
                   && _domain.Equals(cookie._domain, caseInsensitive);
        }

        internal string ToRequestString(Uri uri)
        {
            if (_name.Length == 0)
                return String.Empty;

            if (_version == 0)
                return String.Format("{0}={1}", _name, _value);

            var buff = new StringBuilder(64);

            buff.AppendFormat("$Version={0}; {1}={2}", _version, _name, _value);

            if (!_path.IsNullOrEmpty())
                buff.AppendFormat("; $Path={0}", _path);
            else if (uri != null)
                buff.AppendFormat("; $Path={0}", uri.GetAbsolutePath());
            else
                buff.Append("; $Path=/");

            if (!_domain.IsNullOrEmpty())
            {
                if (uri == null || uri.Host != _domain)
                    buff.AppendFormat("; $Domain={0}", _domain);
            }

            if (_port != null)
            {
                if (_port != "\"\"")
                    buff.AppendFormat("; $Port={0}", _port);
                else
                    buff.Append("; $Port");
            }

            return buff.ToString();
        }

        internal string ToResponseString()
        {
            if (_name.Length == 0)
                return String.Empty;

            if (_version == 0)
                return toResponseStringVersion0();

            return toResponseStringVersion1();
        }

        internal static bool TryCreate(
          string name,
          string value,
          out Cookie result
        )
        {
            result = null;

            try
            {
                result = new Cookie(name, value);
            }
            catch
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Determines whether the current cookie instance is equal to
        /// the specified <see cref="object"/> instance.
        /// </summary>
        /// <param name="comparand">
        ///   <para>
        ///   An <see cref="object"/> instance to compare with
        ///   the current cookie instance.
        ///   </para>
        ///   <para>
        ///   An reference to a <see cref="Cookie"/> instance.
        ///   </para>
        /// </param>
        /// <returns>
        /// <c>true</c> if the current cookie instance is equal to
        /// <paramref name="comparand"/>; otherwise, <c>false</c>.
        /// </returns>
        public override bool Equals(object comparand)
        {
            var cookie = comparand as Cookie;

            if (cookie == null)
                return false;

            var caseSensitive = StringComparison.InvariantCulture;
            var caseInsensitive = StringComparison.InvariantCultureIgnoreCase;

            return _name.Equals(cookie._name, caseInsensitive)
                   && _value.Equals(cookie._value, caseSensitive)
                   && _path.Equals(cookie._path, caseSensitive)
                   && _domain.Equals(cookie._domain, caseInsensitive)
                   && _version == cookie._version;
        }

        /// <summary>
        /// Gets a hash code for the current cookie instance.
        /// </summary>
        /// <returns>
        /// An <see cref="int"/> that represents the hash code.
        /// </returns>
        public override int GetHashCode()
        {
            var i = StringComparer.InvariantCultureIgnoreCase.GetHashCode(_name);
            var j = _value.GetHashCode();
            var k = _path.GetHashCode();
            var l = StringComparer.InvariantCultureIgnoreCase.GetHashCode(_domain);
            var m = _version;

            return hash(i, j, k, l, m);
        }

        /// <summary>
        /// Returns a string that represents the current cookie instance.
        /// </summary>
        /// <returns>
        /// A <see cref="string"/> that is suitable for the Cookie request header.
        /// </returns>
        public override string ToString()
        {
            return ToRequestString(null);
        }
    }
    //=====================================================================================
    /// <summary>
    /// Provides a collection of instances of the <see cref="Cookie"/> class.
    /// </summary>
    [Serializable]
    public class CookieCollection : ICollection<Cookie>
    {
        private List<Cookie> _list;
        private bool _readOnly;
        private object _sync;

        /// <summary>
        /// Initializes a new instance of the <see cref="CookieCollection"/> class.
        /// </summary>
        public CookieCollection()
        {
            _list = new List<Cookie>();
            _sync = ((ICollection)_list).SyncRoot;
        }

        internal IList<Cookie> List
        {
            get
            {
                return _list;
            }
        }

        internal IEnumerable<Cookie> Sorted
        {
            get
            {
                var list = new List<Cookie>(_list);

                if (list.Count > 1)
                    list.Sort(compareForSorted);

                return list;
            }
        }

        /// <summary>
        /// Gets the number of cookies in the collection.
        /// </summary>
        /// <value>
        /// An <see cref="int"/> that represents the number of cookies in
        /// the collection.
        /// </value>
        public int Count
        {
            get
            {
                return _list.Count;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the collection is read-only.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the collection is read-only; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool IsReadOnly
        {
            get
            {
                return _readOnly;
            }

            internal set
            {
                _readOnly = value;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the access to the collection is
        /// thread safe.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the access to the collection is thread safe;
        ///   otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool IsSynchronized
        {
            get
            {
                return false;
            }
        }

        /// <summary>
        /// Gets the cookie at the specified index from the collection.
        /// </summary>
        /// <value>
        /// A <see cref="Cookie"/> at the specified index in the collection.
        /// </value>
        /// <param name="index">
        /// An <see cref="int"/> that specifies the zero-based index of the cookie
        /// to find.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="index"/> is out of allowable range for the collection.
        /// </exception>
        public Cookie this[int index]
        {
            get
            {
                if (index < 0 || index >= _list.Count)
                    throw new ArgumentOutOfRangeException("index");

                return _list[index];
            }
        }

        /// <summary>
        /// Gets the cookie with the specified name from the collection.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="Cookie"/> with the specified name in the collection.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not found.
        ///   </para>
        /// </value>
        /// <param name="name">
        /// A <see cref="string"/> that specifies the name of the cookie to find.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="name"/> is <see langword="null"/>.
        /// </exception>
        public Cookie this[string name]
        {
            get
            {
                if (name == null)
                    throw new ArgumentNullException("name");

                var caseInsensitive = StringComparison.InvariantCultureIgnoreCase;

                foreach (var cookie in Sorted)
                {
                    if (cookie.Name.Equals(name, caseInsensitive))
                        return cookie;
                }

                return null;
            }
        }

        /// <summary>
        /// Gets an object used to synchronize access to the collection.
        /// </summary>
        /// <value>
        /// An <see cref="object"/> used to synchronize access to the collection.
        /// </value>
        public object SyncRoot
        {
            get
            {
                return _sync;
            }
        }

        private void add(Cookie cookie)
        {
            var idx = search(cookie);

            if (idx == -1)
            {
                _list.Add(cookie);

                return;
            }

            _list[idx] = cookie;
        }

        private static int compareForSort(Cookie x, Cookie y)
        {
            return (x.Name.Length + x.Value.Length)
                   - (y.Name.Length + y.Value.Length);
        }

        private static int compareForSorted(Cookie x, Cookie y)
        {
            var ret = x.Version - y.Version;

            if (ret != 0)
                return ret;

            ret = x.Name.CompareTo(y.Name);

            if (ret != 0)
                return ret;

            return y.Path.Length - x.Path.Length;
        }

        private static CookieCollection parseRequest(string value)
        {
            var ret = new CookieCollection();

            Cookie cookie = null;
            var ver = 0;
            var caseInsensitive = StringComparison.InvariantCultureIgnoreCase;

            var pairs = value.SplitHeaderValue(',', ';').ToList();

            for (var i = 0; i < pairs.Count; i++)
            {
                var pair = pairs[i].Trim();

                if (pair.Length == 0)
                    continue;

                var idx = pair.IndexOf('=');

                if (idx == -1)
                {
                    if (cookie == null)
                        continue;

                    if (pair.Equals("$port", caseInsensitive))
                    {
                        cookie.Port = "\"\"";

                        continue;
                    }

                    continue;
                }

                if (idx == 0)
                {
                    if (cookie != null)
                    {
                        ret.add(cookie);

                        cookie = null;
                    }

                    continue;
                }

                var name = pair.Substring(0, idx).TrimEnd(' ');
                var val = idx < pair.Length - 1
                          ? pair.Substring(idx + 1).TrimStart(' ')
                          : String.Empty;

                if (name.Equals("$version", caseInsensitive))
                {
                    if (val.Length == 0)
                        continue;

                    var s = val.Unquote();

                    int num;

                    if (!Int32.TryParse(s, out num))
                        continue;

                    ver = num;

                    continue;
                }

                if (name.Equals("$path", caseInsensitive))
                {
                    if (cookie == null)
                        continue;

                    if (val.Length == 0)
                        continue;

                    cookie.Path = val;

                    continue;
                }

                if (name.Equals("$domain", caseInsensitive))
                {
                    if (cookie == null)
                        continue;

                    if (val.Length == 0)
                        continue;

                    cookie.Domain = val;

                    continue;
                }

                if (name.Equals("$port", caseInsensitive))
                {
                    if (cookie == null)
                        continue;

                    if (val.Length == 0)
                        continue;

                    cookie.Port = val;

                    continue;
                }

                if (cookie != null)
                    ret.add(cookie);

                if (!Cookie.TryCreate(name, val, out cookie))
                    continue;

                if (ver != 0)
                    cookie.Version = ver;
            }

            if (cookie != null)
                ret.add(cookie);

            return ret;
        }

        private static CookieCollection parseResponse(string value)
        {
            var ret = new CookieCollection();

            Cookie cookie = null;
            var caseInsensitive = StringComparison.InvariantCultureIgnoreCase;

            var pairs = value.SplitHeaderValue(',', ';').ToList();

            for (var i = 0; i < pairs.Count; i++)
            {
                var pair = pairs[i].Trim();

                if (pair.Length == 0)
                    continue;

                var idx = pair.IndexOf('=');

                if (idx == -1)
                {
                    if (cookie == null)
                        continue;

                    if (pair.Equals("port", caseInsensitive))
                    {
                        cookie.Port = "\"\"";

                        continue;
                    }

                    if (pair.Equals("discard", caseInsensitive))
                    {
                        cookie.Discard = true;

                        continue;
                    }

                    if (pair.Equals("secure", caseInsensitive))
                    {
                        cookie.Secure = true;

                        continue;
                    }

                    if (pair.Equals("httponly", caseInsensitive))
                    {
                        cookie.HttpOnly = true;

                        continue;
                    }

                    continue;
                }

                if (idx == 0)
                {
                    if (cookie != null)
                    {
                        ret.add(cookie);

                        cookie = null;
                    }

                    continue;
                }

                var name = pair.Substring(0, idx).TrimEnd(' ');
                var val = idx < pair.Length - 1
                          ? pair.Substring(idx + 1).TrimStart(' ')
                          : String.Empty;

                if (name.Equals("version", caseInsensitive))
                {
                    if (cookie == null)
                        continue;

                    if (val.Length == 0)
                        continue;

                    var s = val.Unquote();

                    int num;

                    if (!Int32.TryParse(s, out num))
                        continue;

                    cookie.Version = num;

                    continue;
                }

                if (name.Equals("expires", caseInsensitive))
                {
                    if (val.Length == 0)
                        continue;

                    if (i == pairs.Count - 1)
                        break;

                    i++;

                    if (cookie == null)
                        continue;

                    if (cookie.Expires != DateTime.MinValue)
                        continue;

                    var buff = new StringBuilder(val, 32);

                    buff.AppendFormat(", {0}", pairs[i].Trim());

                    var s = buff.ToString();
                    var fmts = new[] { "ddd, dd'-'MMM'-'yyyy HH':'mm':'ss 'GMT'", "r" };
                    var provider = CultureInfo.CreateSpecificCulture("en-US");
                    var style = DateTimeStyles.AdjustToUniversal
                                | DateTimeStyles.AssumeUniversal;

                    DateTime expires;

                    var done = DateTime.TryParseExact(
                                 s,
                                 fmts,
                                 provider,
                                 style,
                                 out expires
                               );

                    if (!done)
                        continue;

                    cookie.Expires = expires.ToLocalTime();

                    continue;
                }

                if (name.Equals("max-age", caseInsensitive))
                {
                    if (cookie == null)
                        continue;

                    if (val.Length == 0)
                        continue;

                    var s = val.Unquote();

                    int maxAge;

                    if (!Int32.TryParse(s, out maxAge))
                        continue;

                    cookie.MaxAge = maxAge;

                    continue;
                }

                if (name.Equals("path", caseInsensitive))
                {
                    if (cookie == null)
                        continue;

                    if (val.Length == 0)
                        continue;

                    cookie.Path = val;

                    continue;
                }

                if (name.Equals("domain", caseInsensitive))
                {
                    if (cookie == null)
                        continue;

                    if (val.Length == 0)
                        continue;

                    cookie.Domain = val;

                    continue;
                }

                if (name.Equals("port", caseInsensitive))
                {
                    if (cookie == null)
                        continue;

                    if (val.Length == 0)
                        continue;

                    cookie.Port = val;

                    continue;
                }

                if (name.Equals("comment", caseInsensitive))
                {
                    if (cookie == null)
                        continue;

                    if (val.Length == 0)
                        continue;

                    cookie.Comment = urlDecode(val, Encoding.UTF8);

                    continue;
                }

                if (name.Equals("commenturl", caseInsensitive))
                {
                    if (cookie == null)
                        continue;

                    if (val.Length == 0)
                        continue;

                    cookie.CommentUri = val.Unquote().ToUri();

                    continue;
                }

                if (name.Equals("samesite", caseInsensitive))
                {
                    if (cookie == null)
                        continue;

                    if (val.Length == 0)
                        continue;

                    cookie.SameSite = val.Unquote();

                    continue;
                }

                if (cookie != null)
                    ret.add(cookie);

                Cookie.TryCreate(name, val, out cookie);
            }

            if (cookie != null)
                ret.add(cookie);

            return ret;
        }

        private int search(Cookie cookie)
        {
            for (var i = _list.Count - 1; i >= 0; i--)
            {
                if (_list[i].EqualsWithoutValue(cookie))
                    return i;
            }

            return -1;
        }

        private static string urlDecode(string s, Encoding encoding)
        {
            if (s.IndexOfAny(new[] { '%', '+' }) == -1)
                return s;

            try
            {
                return HttpUtility.UrlDecode(s, encoding);
            }
            catch
            {
                return null;
            }
        }

        internal static CookieCollection Parse(string value, bool response)
        {
            try
            {
                return response ? parseResponse(value) : parseRequest(value);
            }
            catch (Exception ex)
            {
                throw new CookieException("It could not be parsed.", ex);
            }
        }

        internal void SetOrRemove(Cookie cookie)
        {
            var idx = search(cookie);

            if (idx == -1)
            {
                if (cookie.Expired)
                    return;

                _list.Add(cookie);

                return;
            }

            if (cookie.Expired)
            {
                _list.RemoveAt(idx);

                return;
            }

            _list[idx] = cookie;
        }

        internal void SetOrRemove(CookieCollection cookies)
        {
            foreach (var cookie in cookies._list)
                SetOrRemove(cookie);
        }

        internal void Sort()
        {
            if (_list.Count < 2)
                return;

            _list.Sort(compareForSort);
        }

        /// <summary>
        /// Adds the specified cookie to the collection.
        /// </summary>
        /// <param name="cookie">
        /// A <see cref="Cookie"/> to add.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="cookie"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The collection is read-only.
        /// </exception>
        public void Add(Cookie cookie)
        {
            if (_readOnly)
            {
                var msg = "The collection is read-only.";

                throw new InvalidOperationException(msg);
            }

            if (cookie == null)
                throw new ArgumentNullException("cookie");

            add(cookie);
        }

        /// <summary>
        /// Adds the specified cookies to the collection.
        /// </summary>
        /// <param name="cookies">
        /// A <see cref="CookieCollection"/> that contains the cookies to add.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="cookies"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The collection is read-only.
        /// </exception>
        public void Add(CookieCollection cookies)
        {
            if (_readOnly)
            {
                var msg = "The collection is read-only.";

                throw new InvalidOperationException(msg);
            }

            if (cookies == null)
                throw new ArgumentNullException("cookies");

            foreach (var cookie in cookies._list)
                add(cookie);
        }

        /// <summary>
        /// Removes all cookies from the collection.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// The collection is read-only.
        /// </exception>
        public void Clear()
        {
            if (_readOnly)
            {
                var msg = "The collection is read-only.";

                throw new InvalidOperationException(msg);
            }

            _list.Clear();
        }

        /// <summary>
        /// Determines whether the collection contains the specified cookie.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the cookie is found in the collection; otherwise,
        /// <c>false</c>.
        /// </returns>
        /// <param name="cookie">
        /// A <see cref="Cookie"/> to find.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="cookie"/> is <see langword="null"/>.
        /// </exception>
        public bool Contains(Cookie cookie)
        {
            if (cookie == null)
                throw new ArgumentNullException("cookie");

            return search(cookie) > -1;
        }

        /// <summary>
        /// Copies the elements of the collection to the specified array,
        /// starting at the specified index.
        /// </summary>
        /// <param name="array">
        /// An array of <see cref="Cookie"/> that specifies the destination of
        /// the elements copied from the collection.
        /// </param>
        /// <param name="index">
        /// An <see cref="int"/> that specifies the zero-based index in
        /// the array at which copying starts.
        /// </param>
        /// <exception cref="ArgumentException">
        /// The space from <paramref name="index"/> to the end of
        /// <paramref name="array"/> is not enough to copy to.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="array"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="index"/> is less than zero.
        /// </exception>
        public void CopyTo(Cookie[] array, int index)
        {
            if (array == null)
                throw new ArgumentNullException("array");

            if (index < 0)
            {
                var msg = "Less than zero.";

                throw new ArgumentOutOfRangeException("index", msg);
            }

            if (array.Length - index < _list.Count)
            {
                var msg = "The available space of the array is not enough to copy to.";

                throw new ArgumentException(msg);
            }

            _list.CopyTo(array, index);
        }

        /// <summary>
        /// Gets the enumerator that iterates through the collection.
        /// </summary>
        /// <returns>
        /// An <see cref="T:System.Collections.Generic.IEnumerator{Cookie}"/>
        /// instance that can be used to iterate through the collection.
        /// </returns>
        public IEnumerator<Cookie> GetEnumerator()
        {
            return _list.GetEnumerator();
        }

        /// <summary>
        /// Removes the specified cookie from the collection.
        /// </summary>
        /// <returns>
        ///   <para>
        ///   <c>true</c> if the cookie is successfully removed; otherwise,
        ///   <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <c>false</c> if the cookie is not found in the collection.
        ///   </para>
        /// </returns>
        /// <param name="cookie">
        /// A <see cref="Cookie"/> to remove.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="cookie"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The collection is read-only.
        /// </exception>
        public bool Remove(Cookie cookie)
        {
            if (_readOnly)
            {
                var msg = "The collection is read-only.";

                throw new InvalidOperationException(msg);
            }

            if (cookie == null)
                throw new ArgumentNullException("cookie");

            var idx = search(cookie);

            if (idx == -1)
                return false;

            _list.RemoveAt(idx);

            return true;
        }

        /// <summary>
        /// Gets the enumerator that iterates through the collection.
        /// </summary>
        /// <returns>
        /// An <see cref="IEnumerator"/> instance that can be used to iterate
        /// through the collection.
        /// </returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return _list.GetEnumerator();
        }
    }
    //============================================================================================
    /// <summary>
    /// The exception that is thrown when a <see cref="Cookie"/> gets an error.
    /// </summary>
    [Serializable]
    public class CookieException : FormatException, ISerializable
    {
        internal CookieException(string message)
          : base(message)
        {
        }

        internal CookieException(string message, Exception innerException)
          : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CookieException"/> class
        /// with the specified serialized data.
        /// </summary>
        /// <param name="serializationInfo">
        /// A <see cref="SerializationInfo"/> that contains the serialized
        /// object data.
        /// </param>
        /// <param name="streamingContext">
        /// A <see cref="StreamingContext"/> that specifies the source for
        /// the deserialization.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="serializationInfo"/> is <see langword="null"/>.
        /// </exception>
        protected CookieException(
          SerializationInfo serializationInfo,
          StreamingContext streamingContext
        )
          : base(serializationInfo, streamingContext)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CookieException"/> class.
        /// </summary>
        public CookieException()
          : base()
        {
        }

        /// <summary>
        /// Populates the specified <see cref="SerializationInfo"/> instance with
        /// the data needed to serialize the current instance.
        /// </summary>
        /// <param name="serializationInfo">
        /// A <see cref="SerializationInfo"/> that holds the serialized object data.
        /// </param>
        /// <param name="streamingContext">
        /// A <see cref="StreamingContext"/> that specifies the destination for
        /// the serialization.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="serializationInfo"/> is <see langword="null"/>.
        /// </exception>
        [
          SecurityPermission(
            SecurityAction.LinkDemand,
            Flags = SecurityPermissionFlag.SerializationFormatter
          )
        ]
        public override void GetObjectData(
          SerializationInfo serializationInfo,
          StreamingContext streamingContext
        )
        {
            base.GetObjectData(serializationInfo, streamingContext);
        }

        /// <summary>
        /// Populates the specified <see cref="SerializationInfo"/> instance with
        /// the data needed to serialize the current instance.
        /// </summary>
        /// <param name="serializationInfo">
        /// A <see cref="SerializationInfo"/> that holds the serialized object data.
        /// </param>
        /// <param name="streamingContext">
        /// A <see cref="StreamingContext"/> that specifies the destination for
        /// the serialization.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="serializationInfo"/> is <see langword="null"/>.
        /// </exception>
        [
          SecurityPermission(
            SecurityAction.LinkDemand,
            Flags = SecurityPermissionFlag.SerializationFormatter,
            SerializationFormatter = true
          )
        ]
        void ISerializable.GetObjectData(
          SerializationInfo serializationInfo,
          StreamingContext streamingContext
        )
        {
            base.GetObjectData(serializationInfo, streamingContext);
        }
    }
    //==================================================================================
    internal sealed class EndPointListener
    {
        private List<HttpListenerPrefix> _all; // host == '+'
        private Dictionary<HttpConnection, HttpConnection> _connections;
        private object _connectionsSync;
        private static readonly string _defaultCertFolderPath;
        private IPEndPoint _endpoint;
        private List<HttpListenerPrefix> _prefixes;
        private bool _secure;
        private Socket _socket;
        private ServerSslConfiguration _sslConfig;
        private List<HttpListenerPrefix> _unhandled; // host == '*'

        static EndPointListener()
        {
            _defaultCertFolderPath = Environment.GetFolderPath(
                                       Environment.SpecialFolder.ApplicationData
                                     );
        }

        internal EndPointListener(
          IPEndPoint endpoint,
          bool secure,
          string certificateFolderPath,
          ServerSslConfiguration sslConfig,
          bool reuseAddress
        )
        {
            _endpoint = endpoint;

            if (secure)
            {
                var cert = getCertificate(
                             endpoint.Port,
                             certificateFolderPath,
                             sslConfig.ServerCertificate
                           );

                if (cert == null)
                {
                    var msg = "No server certificate could be found.";

                    throw new ArgumentException(msg);
                }

                _secure = true;
                _sslConfig = new ServerSslConfiguration(sslConfig);
                _sslConfig.ServerCertificate = cert;
            }

            _prefixes = new List<HttpListenerPrefix>();
            _connections = new Dictionary<HttpConnection, HttpConnection>();
            _connectionsSync = ((ICollection)_connections).SyncRoot;

            _socket = new Socket(
                        endpoint.Address.AddressFamily,
                        SocketType.Stream,
                        ProtocolType.Tcp
                      );

            if (reuseAddress)
            {
                _socket.SetSocketOption(
                  SocketOptionLevel.Socket,
                  SocketOptionName.ReuseAddress,
                  true
                );
            }

            _socket.Bind(endpoint);
            _socket.Listen(500);
            _socket.BeginAccept(onAccept, this);
        }

        public IPAddress Address
        {
            get
            {
                return _endpoint.Address;
            }
        }

        public bool IsSecure
        {
            get
            {
                return _secure;
            }
        }

        public int Port
        {
            get
            {
                return _endpoint.Port;
            }
        }

        public ServerSslConfiguration SslConfiguration
        {
            get
            {
                return _sslConfig;
            }
        }

        private static void addSpecial(
          List<HttpListenerPrefix> prefixes,
          HttpListenerPrefix prefix
        )
        {
            var path = prefix.Path;

            foreach (var pref in prefixes)
            {
                if (pref.Path == path)
                {
                    var msg = "The prefix is already in use.";

                    throw new HttpListenerException(87, msg);
                }
            }

            prefixes.Add(prefix);
        }

        private void clearConnections()
        {
            HttpConnection[] conns = null;

            lock (_connectionsSync)
            {
                var cnt = _connections.Count;

                if (cnt == 0)
                    return;

                conns = new HttpConnection[cnt];

                _connections.Values.CopyTo(conns, 0);
                _connections.Clear();
            }

            foreach (var conn in conns)
                conn.Close(true);
        }

        private static RSACryptoServiceProvider createRSAFromFile(string path)
        {
            var rsa = new RSACryptoServiceProvider();

            var key = File.ReadAllBytes(path);

            rsa.ImportCspBlob(key);

            return rsa;
        }

        private static X509Certificate2 getCertificate(
          int port,
          string folderPath,
          X509Certificate2 defaultCertificate
        )
        {
            if (folderPath == null || folderPath.Length == 0)
                folderPath = _defaultCertFolderPath;

            try
            {
                var cer = Path.Combine(folderPath, String.Format("{0}.cer", port));
                var key = Path.Combine(folderPath, String.Format("{0}.key", port));

                var exists = File.Exists(cer) && File.Exists(key);

                if (!exists)
                    return defaultCertificate;

                var cert = new X509Certificate2(cer);

                cert.PrivateKey = createRSAFromFile(key);

                return cert;
            }
            catch
            {
                return defaultCertificate;
            }
        }

        private void leaveIfNoPrefix()
        {
            if (_prefixes.Count > 0)
                return;

            var prefs = _unhandled;

            if (prefs != null && prefs.Count > 0)
                return;

            prefs = _all;

            if (prefs != null && prefs.Count > 0)
                return;

            Close();
        }

        private static void onAccept(IAsyncResult asyncResult)
        {
            var lsnr = (EndPointListener)asyncResult.AsyncState;

            Socket sock = null;

            try
            {
                sock = lsnr._socket.EndAccept(asyncResult);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (Exception)
            {
                // TODO: Logging.
            }

            try
            {
                lsnr._socket.BeginAccept(onAccept, lsnr);
            }
            catch (Exception)
            {
                // TODO: Logging.

                if (sock != null)
                    sock.Close();

                return;
            }

            if (sock == null)
                return;

            processAccepted(sock, lsnr);
        }

        private static void processAccepted(
          Socket socket,
          EndPointListener listener
        )
        {
            HttpConnection conn = null;

            try
            {
                conn = new HttpConnection(socket, listener);
            }
            catch (Exception)
            {
                // TODO: Logging.

                socket.Close();

                return;
            }

            lock (listener._connectionsSync)
                listener._connections.Add(conn, conn);

            conn.BeginReadRequest();
        }

        private static bool removeSpecial(
          List<HttpListenerPrefix> prefixes,
          HttpListenerPrefix prefix
        )
        {
            var path = prefix.Path;
            var cnt = prefixes.Count;

            for (var i = 0; i < cnt; i++)
            {
                if (prefixes[i].Path == path)
                {
                    prefixes.RemoveAt(i);

                    return true;
                }
            }

            return false;
        }

        private static HttpListener searchHttpListenerFromSpecial(
          string path,
          List<HttpListenerPrefix> prefixes
        )
        {
            if (prefixes == null)
                return null;

            HttpListener ret = null;

            var bestLen = -1;

            foreach (var pref in prefixes)
            {
                var prefPath = pref.Path;
                var len = prefPath.Length;

                if (len < bestLen)
                    continue;

                var match = path.StartsWith(prefPath, StringComparison.Ordinal);

                if (!match)
                    continue;

                bestLen = len;
                ret = pref.Listener;
            }

            return ret;
        }

        internal static bool CertificateExists(int port, string folderPath)
        {
            if (folderPath == null || folderPath.Length == 0)
                folderPath = _defaultCertFolderPath;

            var cer = Path.Combine(folderPath, String.Format("{0}.cer", port));
            var key = Path.Combine(folderPath, String.Format("{0}.key", port));

            return File.Exists(cer) && File.Exists(key);
        }

        internal void RemoveConnection(HttpConnection connection)
        {
            lock (_connectionsSync)
                _connections.Remove(connection);
        }

        internal bool TrySearchHttpListener(Uri uri, out HttpListener listener)
        {
            listener = null;

            if (uri == null)
                return false;

            var host = uri.Host;
            var dns = Uri.CheckHostName(host) == UriHostNameType.Dns;
            var port = uri.Port.ToString();
            var path = HttpUtility.UrlDecode(uri.AbsolutePath);

            if (path[path.Length - 1] != '/')
                path += "/";

            if (host != null && host.Length > 0)
            {
                var prefs = _prefixes;
                var bestLen = -1;

                foreach (var pref in prefs)
                {
                    if (dns)
                    {
                        var prefHost = pref.Host;
                        var prefDns = Uri.CheckHostName(prefHost) == UriHostNameType.Dns;

                        if (prefDns)
                        {
                            if (prefHost != host)
                                continue;
                        }
                    }

                    if (pref.Port != port)
                        continue;

                    var prefPath = pref.Path;
                    var len = prefPath.Length;

                    if (len < bestLen)
                        continue;

                    var match = path.StartsWith(prefPath, StringComparison.Ordinal);

                    if (!match)
                        continue;

                    bestLen = len;
                    listener = pref.Listener;
                }

                if (bestLen != -1)
                    return true;
            }

            listener = searchHttpListenerFromSpecial(path, _unhandled);

            if (listener != null)
                return true;

            listener = searchHttpListenerFromSpecial(path, _all);

            return listener != null;
        }

        public void AddPrefix(HttpListenerPrefix prefix)
        {
            List<HttpListenerPrefix> current, future;

            if (prefix.Host == "*")
            {
                do
                {
                    current = _unhandled;
                    future = current != null
                             ? new List<HttpListenerPrefix>(current)
                             : new List<HttpListenerPrefix>();

                    addSpecial(future, prefix);
                }
                while (
                  Interlocked.CompareExchange(ref _unhandled, future, current)
                  != current
                );

                return;
            }

            if (prefix.Host == "+")
            {
                do
                {
                    current = _all;
                    future = current != null
                             ? new List<HttpListenerPrefix>(current)
                             : new List<HttpListenerPrefix>();

                    addSpecial(future, prefix);
                }
                while (
                  Interlocked.CompareExchange(ref _all, future, current)
                  != current
                );

                return;
            }

            do
            {
                current = _prefixes;

                var idx = current.IndexOf(prefix);

                if (idx > -1)
                {
                    if (current[idx].Listener != prefix.Listener)
                    {
                        var fmt = "There is another listener for {0}.";
                        var msg = String.Format(fmt, prefix);

                        throw new HttpListenerException(87, msg);
                    }

                    return;
                }

                future = new List<HttpListenerPrefix>(current);

                future.Add(prefix);
            }
            while (
              Interlocked.CompareExchange(ref _prefixes, future, current)
              != current
            );
        }

        public void Close()
        {
            _socket.Close();

            clearConnections();
            EndPointManager.RemoveEndPoint(_endpoint);
        }

        public void RemovePrefix(HttpListenerPrefix prefix)
        {
            List<HttpListenerPrefix> current, future;

            if (prefix.Host == "*")
            {
                do
                {
                    current = _unhandled;

                    if (current == null)
                        break;

                    future = new List<HttpListenerPrefix>(current);

                    if (!removeSpecial(future, prefix))
                        break;
                }
                while (
                  Interlocked.CompareExchange(ref _unhandled, future, current)
                  != current
                );

                leaveIfNoPrefix();

                return;
            }

            if (prefix.Host == "+")
            {
                do
                {
                    current = _all;

                    if (current == null)
                        break;

                    future = new List<HttpListenerPrefix>(current);

                    if (!removeSpecial(future, prefix))
                        break;
                }
                while (
                  Interlocked.CompareExchange(ref _all, future, current)
                  != current
                );

                leaveIfNoPrefix();

                return;
            }

            do
            {
                current = _prefixes;

                if (!current.Contains(prefix))
                    break;

                future = new List<HttpListenerPrefix>(current);

                future.Remove(prefix);
            }
            while (
              Interlocked.CompareExchange(ref _prefixes, future, current)
              != current
            );

            leaveIfNoPrefix();
        }
    }
    //===================================================================================
    internal sealed class EndPointManager
    {
        private static readonly Dictionary<IPEndPoint, EndPointListener> _endpoints;

        static EndPointManager()
        {
            _endpoints = new Dictionary<IPEndPoint, EndPointListener>();
        }

        private EndPointManager()
        {
        }

        private static void addPrefix(string uriPrefix, HttpListener listener)
        {
            var pref = new HttpListenerPrefix(uriPrefix, listener);

            var addr = convertToIPAddress(pref.Host);

            if (addr == null)
            {
                var msg = "The URI prefix includes an invalid host.";

                throw new HttpListenerException(87, msg);
            }

            if (!addr.IsLocal())
            {
                var msg = "The URI prefix includes an invalid host.";

                throw new HttpListenerException(87, msg);
            }

            int port;

            if (!Int32.TryParse(pref.Port, out port))
            {
                var msg = "The URI prefix includes an invalid port.";

                throw new HttpListenerException(87, msg);
            }

            if (!port.IsPortNumber())
            {
                var msg = "The URI prefix includes an invalid port.";

                throw new HttpListenerException(87, msg);
            }

            var path = pref.Path;

            if (path.IndexOf('%') != -1)
            {
                var msg = "The URI prefix includes an invalid path.";

                throw new HttpListenerException(87, msg);
            }

            if (path.IndexOf("//", StringComparison.Ordinal) != -1)
            {
                var msg = "The URI prefix includes an invalid path.";

                throw new HttpListenerException(87, msg);
            }

            var endpoint = new IPEndPoint(addr, port);

            EndPointListener lsnr;

            if (_endpoints.TryGetValue(endpoint, out lsnr))
            {
                if (lsnr.IsSecure ^ pref.IsSecure)
                {
                    var msg = "The URI prefix includes an invalid scheme.";

                    throw new HttpListenerException(87, msg);
                }
            }
            else
            {
                lsnr = new EndPointListener(
                         endpoint,
                         pref.IsSecure,
                         listener.CertificateFolderPath,
                         listener.SslConfiguration,
                         listener.ReuseAddress
                       );

                _endpoints.Add(endpoint, lsnr);
            }

            lsnr.AddPrefix(pref);
        }

        private static IPAddress convertToIPAddress(string hostname)
        {
            if (hostname == "*")
                return IPAddress.Any;

            if (hostname == "+")
                return IPAddress.Any;

            return hostname.ToIPAddress();
        }

        private static void removePrefix(string uriPrefix, HttpListener listener)
        {
            var pref = new HttpListenerPrefix(uriPrefix, listener);

            var addr = convertToIPAddress(pref.Host);

            if (addr == null)
                return;

            if (!addr.IsLocal())
                return;

            int port;

            if (!Int32.TryParse(pref.Port, out port))
                return;

            if (!port.IsPortNumber())
                return;

            var path = pref.Path;

            if (path.IndexOf('%') != -1)
                return;

            if (path.IndexOf("//", StringComparison.Ordinal) != -1)
                return;

            var endpoint = new IPEndPoint(addr, port);

            EndPointListener lsnr;

            if (!_endpoints.TryGetValue(endpoint, out lsnr))
                return;

            if (lsnr.IsSecure ^ pref.IsSecure)
                return;

            lsnr.RemovePrefix(pref);
        }

        internal static bool RemoveEndPoint(IPEndPoint endpoint)
        {
            lock (((ICollection)_endpoints).SyncRoot)
                return _endpoints.Remove(endpoint);
        }

        public static void AddListener(HttpListener listener)
        {
            var added = new List<string>();

            lock (((ICollection)_endpoints).SyncRoot)
            {
                try
                {
                    foreach (var pref in listener.Prefixes)
                    {
                        addPrefix(pref, listener);
                        added.Add(pref);
                    }
                }
                catch
                {
                    foreach (var pref in added)
                        removePrefix(pref, listener);

                    throw;
                }
            }
        }

        public static void AddPrefix(string uriPrefix, HttpListener listener)
        {
            lock (((ICollection)_endpoints).SyncRoot)
                addPrefix(uriPrefix, listener);
        }

        public static void RemoveListener(HttpListener listener)
        {
            lock (((ICollection)_endpoints).SyncRoot)
            {
                foreach (var pref in listener.Prefixes)
                    removePrefix(pref, listener);
            }
        }

        public static void RemovePrefix(string uriPrefix, HttpListener listener)
        {
            lock (((ICollection)_endpoints).SyncRoot)
                removePrefix(uriPrefix, listener);
        }
    }
    //====================================================================================
    /// <summary>
    /// Holds the username and password from an HTTP Basic authentication attempt.
    /// </summary>
    public class HttpBasicIdentity : GenericIdentity
    {
        private string _password;

        internal HttpBasicIdentity(string username, string password)
          : base(username, "Basic")
        {
            _password = password;
        }

        /// <summary>
        /// Gets the password from a basic authentication attempt.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the password.
        /// </value>
        public virtual string Password
        {
            get
            {
                return _password;
            }
        }
    }
    //===================================================================================
    internal sealed class HttpConnection
    {
        private int _attempts;
        private byte[] _buffer;
        private static readonly int _bufferLength;
        private HttpListenerContext _context;
        private StringBuilder _currentLine;
        private EndPointListener _endPointListener;
        private InputState _inputState;
        private RequestStream _inputStream;
        private bool _isSecure;
        private LineState _lineState;
        private EndPoint _localEndPoint;
        private static readonly int _maxInputLength;
        private ResponseStream _outputStream;
        private int _position;
        private EndPoint _remoteEndPoint;
        private MemoryStream _requestBuffer;
        private int _reuses;
        private Socket _socket;
        private Stream _stream;
        private object _sync;
        private int _timeout;
        private Dictionary<int, bool> _timeoutCanceled;
        private Timer _timer;

        static HttpConnection()
        {
            _bufferLength = 8192;
            _maxInputLength = 32768;
        }

        internal HttpConnection(Socket socket, EndPointListener listener)
        {
            _socket = socket;
            _endPointListener = listener;

            var netStream = new NetworkStream(socket, false);

            if (listener.IsSecure)
            {
                var sslConf = listener.SslConfiguration;
                var sslStream = new SslStream(
                                  netStream,
                                  false,
                                  sslConf.ClientCertificateValidationCallback
                                );

                sslStream.AuthenticateAsServer(
                  sslConf.ServerCertificate,
                  sslConf.ClientCertificateRequired,
                  sslConf.EnabledSslProtocols,
                  sslConf.CheckCertificateRevocation
                );

                _isSecure = true;
                _stream = sslStream;
            }
            else
            {
                _stream = netStream;
            }

            _buffer = new byte[_bufferLength];
            _localEndPoint = socket.LocalEndPoint;
            _remoteEndPoint = socket.RemoteEndPoint;
            _sync = new object();
            _timeoutCanceled = new Dictionary<int, bool>();
            _timer = new Timer(onTimeout, this, Timeout.Infinite, Timeout.Infinite);

            // 90k ms for first request, 15k ms from then on.
            init(new MemoryStream(), 90000);
        }

        public bool IsClosed
        {
            get
            {
                return _socket == null;
            }
        }

        public bool IsLocal
        {
            get
            {
                return ((IPEndPoint)_remoteEndPoint).Address.IsLocal();
            }
        }

        public bool IsSecure
        {
            get
            {
                return _isSecure;
            }
        }

        public IPEndPoint LocalEndPoint
        {
            get
            {
                return (IPEndPoint)_localEndPoint;
            }
        }

        public IPEndPoint RemoteEndPoint
        {
            get
            {
                return (IPEndPoint)_remoteEndPoint;
            }
        }

        public int Reuses
        {
            get
            {
                return _reuses;
            }
        }

        public Socket Socket
        {
            get
            {
                return _socket;
            }
        }

        public Stream Stream
        {
            get
            {
                return _stream;
            }
        }

        private void close()
        {
            lock (_sync)
            {
                if (_socket == null)
                    return;

                disposeTimer();
                disposeRequestBuffer();
                disposeStream();
                closeSocket();
            }

            _context.Unregister();
            _endPointListener.RemoveConnection(this);
        }

        private void closeSocket()
        {
            try
            {
                _socket.Shutdown(SocketShutdown.Both);
            }
            catch
            {
            }

            _socket.Close();

            _socket = null;
        }

        private static MemoryStream createRequestBuffer(
          RequestStream inputStream
        )
        {
            var ret = new MemoryStream();

            if (inputStream is ChunkedRequestStream)
            {
                var crs = (ChunkedRequestStream)inputStream;

                if (crs.HasRemainingBuffer)
                {
                    var buff = crs.RemainingBuffer;

                    ret.Write(buff, 0, buff.Length);
                }

                return ret;
            }

            var cnt = inputStream.Count;

            if (cnt > 0)
                ret.Write(inputStream.InitialBuffer, inputStream.Offset, cnt);

            return ret;
        }

        private void disposeRequestBuffer()
        {
            if (_requestBuffer == null)
                return;

            _requestBuffer.Dispose();

            _requestBuffer = null;
        }

        private void disposeStream()
        {
            if (_stream == null)
                return;

            _stream.Dispose();

            _stream = null;
        }

        private void disposeTimer()
        {
            if (_timer == null)
                return;

            try
            {
                _timer.Change(Timeout.Infinite, Timeout.Infinite);
            }
            catch
            {
            }

            _timer.Dispose();

            _timer = null;
        }

        private void init(MemoryStream requestBuffer, int timeout)
        {
            _requestBuffer = requestBuffer;
            _timeout = timeout;

            _context = new HttpListenerContext(this);
            _currentLine = new StringBuilder(64);
            _inputState = InputState.RequestLine;
            _inputStream = null;
            _lineState = LineState.None;
            _outputStream = null;
            _position = 0;
        }

        private static void onRead(IAsyncResult asyncResult)
        {
            var conn = (HttpConnection)asyncResult.AsyncState;
            var current = conn._attempts;

            if (conn._socket == null)
                return;

            lock (conn._sync)
            {
                if (conn._socket == null)
                    return;

                conn._timer.Change(Timeout.Infinite, Timeout.Infinite);
                conn._timeoutCanceled[current] = true;

                var nread = 0;

                try
                {
                    nread = conn._stream.EndRead(asyncResult);
                }
                catch (Exception)
                {
                    // TODO: Logging.

                    conn.close();

                    return;
                }

                if (nread <= 0)
                {
                    conn.close();

                    return;
                }

                conn._requestBuffer.Write(conn._buffer, 0, nread);

                if (conn.processRequestBuffer())
                    return;

                conn.BeginReadRequest();
            }
        }

        private static void onTimeout(object state)
        {
            var conn = (HttpConnection)state;
            var current = conn._attempts;

            if (conn._socket == null)
                return;

            lock (conn._sync)
            {
                if (conn._socket == null)
                    return;

                if (conn._timeoutCanceled[current])
                    return;

                conn._context.SendError(408);
            }
        }

        private bool processInput(byte[] data, int length)
        {
            // This method returns a bool:
            // - true  Done processing
            // - false Need more input

            var req = _context.Request;

            try
            {
                while (true)
                {
                    int nread;
                    var line = readLineFrom(data, _position, length, out nread);

                    _position += nread;

                    if (line == null)
                        break;

                    if (line.Length == 0)
                    {
                        if (_inputState == InputState.RequestLine)
                            continue;

                        if (_position > _maxInputLength)
                            _context.ErrorMessage = "Headers too long";

                        return true;
                    }

                    if (_inputState == InputState.RequestLine)
                    {
                        req.SetRequestLine(line);

                        _inputState = InputState.Headers;
                    }
                    else
                    {
                        req.AddHeader(line);
                    }

                    if (_context.HasErrorMessage)
                        return true;
                }
            }
            catch (Exception)
            {
                // TODO: Logging.

                _context.ErrorMessage = "Processing failure";

                return true;
            }

            if (_position >= _maxInputLength)
            {
                _context.ErrorMessage = "Headers too long";

                return true;
            }

            return false;
        }

        private bool processRequestBuffer()
        {
            // This method returns a bool:
            // - true  Done processing
            // - false Need more write

            var data = _requestBuffer.GetBuffer();
            var len = (int)_requestBuffer.Length;

            if (!processInput(data, len))
                return false;

            var req = _context.Request;

            if (!_context.HasErrorMessage)
                req.FinishInitialization();

            if (_context.HasErrorMessage)
            {
                _context.SendError();

                return true;
            }

            var uri = req.Url;
            HttpListener httplsnr;

            if (!_endPointListener.TrySearchHttpListener(uri, out httplsnr))
            {
                _context.SendError(404);

                return true;
            }

            httplsnr.RegisterContext(_context);

            return true;
        }

        private string readLineFrom(
          byte[] buffer,
          int offset,
          int length,
          out int nread
        )
        {
            nread = 0;

            for (var i = offset; i < length; i++)
            {
                nread++;

                var b = buffer[i];

                if (b == 13)
                {
                    _lineState = LineState.Cr;

                    continue;
                }

                if (b == 10)
                {
                    _lineState = LineState.Lf;

                    break;
                }

                _currentLine.Append((char)b);
            }

            if (_lineState != LineState.Lf)
                return null;

            var ret = _currentLine.ToString();

            _currentLine.Length = 0;
            _lineState = LineState.None;

            return ret;
        }

        private MemoryStream takeOverRequestBuffer()
        {
            if (_inputStream != null)
                return createRequestBuffer(_inputStream);

            var ret = new MemoryStream();

            var buff = _requestBuffer.GetBuffer();
            var len = (int)_requestBuffer.Length;
            var cnt = len - _position;

            if (cnt > 0)
                ret.Write(buff, _position, cnt);

            disposeRequestBuffer();

            return ret;
        }

        internal void BeginReadRequest()
        {
            _attempts++;

            _timeoutCanceled.Add(_attempts, false);
            _timer.Change(_timeout, Timeout.Infinite);

            try
            {
                _stream.BeginRead(_buffer, 0, _bufferLength, onRead, this);
            }
            catch (Exception)
            {
                // TODO: Logging.

                close();
            }
        }

        internal void Close(bool force)
        {
            if (_socket == null)
                return;

            lock (_sync)
            {
                if (_socket == null)
                    return;

                if (force)
                {
                    if (_outputStream != null)
                        _outputStream.Close(true);

                    close();

                    return;
                }

                GetResponseStream().Close(false);

                if (_context.Response.CloseConnection)
                {
                    close();

                    return;
                }

                if (!_context.Request.FlushInput())
                {
                    close();

                    return;
                }

                _context.Unregister();

                _reuses++;

                var buff = takeOverRequestBuffer();
                var len = buff.Length;

                init(buff, 15000);

                if (len > 0)
                {
                    if (processRequestBuffer())
                        return;
                }

                BeginReadRequest();
            }
        }

        public void Close()
        {
            Close(false);
        }

        public RequestStream GetRequestStream(long contentLength, bool chunked)
        {
            lock (_sync)
            {
                if (_socket == null)
                    return null;

                if (_inputStream != null)
                    return _inputStream;

                var buff = _requestBuffer.GetBuffer();
                var len = (int)_requestBuffer.Length;
                var cnt = len - _position;

                _inputStream = chunked
                               ? new ChunkedRequestStream(
                                   _stream,
                                   buff,
                                   _position,
                                   cnt,
                                   _context
                                 )
                               : new RequestStream(
                                   _stream,
                                   buff,
                                   _position,
                                   cnt,
                                   contentLength
                                 );

                disposeRequestBuffer();

                return _inputStream;
            }
        }

        public ResponseStream GetResponseStream()
        {
            lock (_sync)
            {
                if (_socket == null)
                    return null;

                if (_outputStream != null)
                    return _outputStream;

                var lsnr = _context.Listener;
                var ignore = lsnr != null ? lsnr.IgnoreWriteExceptions : true;

                _outputStream = new ResponseStream(_stream, _context.Response, ignore);

                return _outputStream;
            }
        }
    }
    //===============================================================================
    /// <summary>
    /// Holds the username and other parameters from an HTTP Digest
    /// authentication attempt.
    /// </summary>
    public class HttpDigestIdentity : GenericIdentity
    {
        private NameValueCollection _parameters;

        internal HttpDigestIdentity(NameValueCollection parameters)
          : base(parameters["username"], "Digest")
        {
            _parameters = parameters;
        }

        /// <summary>
        /// Gets the algorithm parameter from a digest authentication attempt.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the algorithm parameter.
        /// </value>
        public string Algorithm
        {
            get
            {
                return _parameters["algorithm"];
            }
        }

        /// <summary>
        /// Gets the cnonce parameter from a digest authentication attempt.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the cnonce parameter.
        /// </value>
        public string Cnonce
        {
            get
            {
                return _parameters["cnonce"];
            }
        }

        /// <summary>
        /// Gets the nc parameter from a digest authentication attempt.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the nc parameter.
        /// </value>
        public string Nc
        {
            get
            {
                return _parameters["nc"];
            }
        }

        /// <summary>
        /// Gets the nonce parameter from a digest authentication attempt.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the nonce parameter.
        /// </value>
        public string Nonce
        {
            get
            {
                return _parameters["nonce"];
            }
        }

        /// <summary>
        /// Gets the opaque parameter from a digest authentication attempt.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the opaque parameter.
        /// </value>
        public string Opaque
        {
            get
            {
                return _parameters["opaque"];
            }
        }

        /// <summary>
        /// Gets the qop parameter from a digest authentication attempt.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the qop parameter.
        /// </value>
        public string Qop
        {
            get
            {
                return _parameters["qop"];
            }
        }

        /// <summary>
        /// Gets the realm parameter from a digest authentication attempt.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the realm parameter.
        /// </value>
        public string Realm
        {
            get
            {
                return _parameters["realm"];
            }
        }

        /// <summary>
        /// Gets the response parameter from a digest authentication attempt.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the response parameter.
        /// </value>
        public string Response
        {
            get
            {
                return _parameters["response"];
            }
        }

        /// <summary>
        /// Gets the uri parameter from a digest authentication attempt.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the uri parameter.
        /// </value>
        public string Uri
        {
            get
            {
                return _parameters["uri"];
            }
        }

        internal bool IsValid(
          string password,
          string realm,
          string method,
          string entity
        )
        {
            var parameters = new NameValueCollection(_parameters);

            parameters["password"] = password;
            parameters["realm"] = realm;
            parameters["method"] = method;
            parameters["entity"] = entity;

            var expectedDigest = AuthenticationResponse.CreateRequestDigest(parameters);

            return _parameters["response"] == expectedDigest;
        }
    }
    //============================================================================================
    internal class HttpHeaderInfo
    {
        private string _headerName;
        private HttpHeaderType _headerType;

        internal HttpHeaderInfo(string headerName, HttpHeaderType headerType)
        {
            _headerName = headerName;
            _headerType = headerType;
        }

        internal bool IsMultiValueInRequest
        {
            get
            {
                var headerType = _headerType & HttpHeaderType.MultiValueInRequest;

                return headerType == HttpHeaderType.MultiValueInRequest;
            }
        }

        internal bool IsMultiValueInResponse
        {
            get
            {
                var headerType = _headerType & HttpHeaderType.MultiValueInResponse;

                return headerType == HttpHeaderType.MultiValueInResponse;
            }
        }

        public string HeaderName
        {
            get
            {
                return _headerName;
            }
        }

        public HttpHeaderType HeaderType
        {
            get
            {
                return _headerType;
            }
        }

        public bool IsRequest
        {
            get
            {
                var headerType = _headerType & HttpHeaderType.Request;

                return headerType == HttpHeaderType.Request;
            }
        }

        public bool IsResponse
        {
            get
            {
                var headerType = _headerType & HttpHeaderType.Response;

                return headerType == HttpHeaderType.Response;
            }
        }

        public bool IsMultiValue(bool response)
        {
            var headerType = _headerType & HttpHeaderType.MultiValue;

            if (headerType != HttpHeaderType.MultiValue)
                return response ? IsMultiValueInResponse : IsMultiValueInRequest;

            return response ? IsResponse : IsRequest;
        }

        public bool IsRestricted(bool response)
        {
            var headerType = _headerType & HttpHeaderType.Restricted;

            if (headerType != HttpHeaderType.Restricted)
                return false;

            return response ? IsResponse : IsRequest;
        }
    }
    //=============================================================================
    [Flags]
    internal enum HttpHeaderType
    {
        Unspecified = 0,
        Request = 1,
        Response = 1 << 1,
        Restricted = 1 << 2,
        MultiValue = 1 << 3,
        MultiValueInRequest = 1 << 4,
        MultiValueInResponse = 1 << 5
    }
    //=============================================================================
    /// <summary>
    /// Provides a simple, programmatically controlled HTTP listener.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///   The listener supports HTTP/1.1 version request and response.
    ///   </para>
    ///   <para>
    ///   And the listener allows to accept WebSocket handshake requests.
    ///   </para>
    ///   <para>
    ///   This class cannot be inherited.
    ///   </para>
    /// </remarks>
    public sealed class HttpListener : IDisposable
    {
        private AuthenticationSchemes _authSchemes;
        private Func<HttpListenerRequest, AuthenticationSchemes> _authSchemeSelector;
        private string _certFolderPath;
        private Queue<HttpListenerContext> _contextQueue;
        private LinkedList<HttpListenerContext> _contextRegistry;
        private object _contextRegistrySync;
        private static readonly string _defaultRealm;
        private bool _disposed;
        private bool _ignoreWriteExceptions;
        private volatile bool _isListening;
        private Logger _log;
        private HttpListenerPrefixCollection _prefixes;
        private string _realm;
        private bool _reuseAddress;
        private ServerSslConfiguration _sslConfig;
        private object _sync;
        private Func<IIdentity, NetworkCredential> _userCredFinder;
        private Queue<HttpListenerAsyncResult> _waitQueue;

        static HttpListener()
        {
            _defaultRealm = "SECRET AREA";
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpListener"/> class.
        /// </summary>
        public HttpListener()
        {
            _authSchemes = AuthenticationSchemes.Anonymous;
            _contextQueue = new Queue<HttpListenerContext>();
            _contextRegistry = new LinkedList<HttpListenerContext>();
            _contextRegistrySync = ((ICollection)_contextRegistry).SyncRoot;
            _log = new Logger();
            _prefixes = new HttpListenerPrefixCollection(this);
            _sync = new object();
            _waitQueue = new Queue<HttpListenerAsyncResult>();
        }

        internal string ObjectName
        {
            get
            {
                return GetType().ToString();
            }
        }

        internal bool ReuseAddress
        {
            get
            {
                return _reuseAddress;
            }

            set
            {
                _reuseAddress = value;
            }
        }

        /// <summary>
        /// Gets or sets the scheme used to authenticate the clients.
        /// </summary>
        /// <value>
        ///   <para>
        ///   One of the <see cref="WebSocketSharp.Net.AuthenticationSchemes"/>
        ///   enum values.
        ///   </para>
        ///   <para>
        ///   It represents the scheme used to authenticate the clients.
        ///   </para>
        ///   <para>
        ///   The default value is
        ///   <see cref="WebSocketSharp.Net.AuthenticationSchemes.Anonymous"/>.
        ///   </para>
        /// </value>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public AuthenticationSchemes AuthenticationSchemes
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                return _authSchemes;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                _authSchemes = value;
            }
        }

        /// <summary>
        /// Gets or sets the delegate called to determine the scheme used to
        /// authenticate the clients.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   If this property is set, the listener uses the authentication
        ///   scheme selected by the delegate for each request.
        ///   </para>
        ///   <para>
        ///   Or if this property is not set, the listener uses the value of
        ///   the <see cref="HttpListener.AuthenticationSchemes"/> property
        ///   as the authentication scheme for all requests.
        ///   </para>
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="T:System.Func{HttpListenerRequest, AuthenticationSchemes}"/>
        ///   delegate.
        ///   </para>
        ///   <para>
        ///   It represents the delegate called when the listener selects
        ///   an authentication scheme.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public Func<HttpListenerRequest, AuthenticationSchemes> AuthenticationSchemeSelector
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                return _authSchemeSelector;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                _authSchemeSelector = value;
            }
        }

        /// <summary>
        /// Gets or sets the path to the folder in which stores the certificate
        /// files used to authenticate the server on the secure connection.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This property represents the path to the folder in which stores
        ///   the certificate files associated with each port number of added
        ///   URI prefixes.
        ///   </para>
        ///   <para>
        ///   A set of the certificate files is a pair of &lt;port number&gt;.cer
        ///   (DER) and &lt;port number&gt;.key (DER, RSA Private Key).
        ///   </para>
        ///   <para>
        ///   If this property is <see langword="null"/> or an empty string,
        ///   the result of the <see cref="Environment.SpecialFolder.ApplicationData"/>
        ///   with the <see cref="Environment.GetFolderPath"/> method is used as
        ///   the default path.
        ///   </para>
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the path to the folder
        ///   in which stores the certificate files.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public string CertificateFolderPath
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                return _certFolderPath;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                _certFolderPath = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the listener returns
        /// exceptions that occur when sending the response to the client.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the listener should not return those exceptions;
        ///   otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public bool IgnoreWriteExceptions
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                return _ignoreWriteExceptions;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                _ignoreWriteExceptions = value;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the listener has been started.
        /// </summary>
        /// <value>
        /// <c>true</c> if the listener has been started; otherwise, <c>false</c>.
        /// </value>
        public bool IsListening
        {
            get
            {
                return _isListening;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the listener can be used with
        /// the current operating system.
        /// </summary>
        /// <value>
        /// <c>true</c>.
        /// </value>
        public static bool IsSupported
        {
            get
            {
                return true;
            }
        }

        /// <summary>
        /// Gets the logging functions.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   The default logging level is <see cref="LogLevel.Error"/>.
        ///   </para>
        ///   <para>
        ///   If you would like to change it, you should set the <c>Log.Level</c>
        ///   property to any of the <see cref="LogLevel"/> enum values.
        ///   </para>
        /// </remarks>
        /// <value>
        /// A <see cref="Logger"/> that provides the logging functions.
        /// </value>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public Logger Log
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                return _log;
            }
        }

        /// <summary>
        /// Gets the URI prefixes handled by the listener.
        /// </summary>
        /// <value>
        /// A <see cref="HttpListenerPrefixCollection"/> that contains the URI
        /// prefixes.
        /// </value>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public HttpListenerPrefixCollection Prefixes
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                return _prefixes;
            }
        }

        /// <summary>
        /// Gets or sets the name of the realm associated with the listener.
        /// </summary>
        /// <remarks>
        /// If this property is <see langword="null"/> or an empty string,
        /// "SECRET AREA" is used as the name of the realm.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the name of the realm.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public string Realm
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                return _realm;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                _realm = value;
            }
        }

        /// <summary>
        /// Gets the configuration for secure connection.
        /// </summary>
        /// <value>
        /// A <see cref="ServerSslConfiguration"/> that represents the
        /// configuration used to provide secure connections.
        /// </value>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public ServerSslConfiguration SslConfiguration
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                if (_sslConfig == null)
                    _sslConfig = new ServerSslConfiguration();

                return _sslConfig;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether, when NTLM authentication is used,
        /// the authentication information of first request is used to authenticate
        /// additional requests on the same connection.
        /// </summary>
        /// <remarks>
        /// This property is not currently supported and always throws
        /// a <see cref="NotSupportedException"/>.
        /// </remarks>
        /// <value>
        /// <c>true</c> if the authentication information of first request is used;
        /// otherwise, <c>false</c>.
        /// </value>
        /// <exception cref="NotSupportedException">
        /// Any use of this property.
        /// </exception>
        public bool UnsafeConnectionNtlmAuthentication
        {
            get
            {
                throw new NotSupportedException();
            }

            set
            {
                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets or sets the delegate called to find the credentials for
        /// an identity used to authenticate a client.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="T:System.Func{IIdentity, NetworkCredential}"/>
        ///   delegate.
        ///   </para>
        ///   <para>
        ///   It represents the delegate called when the listener finds
        ///   the credentials used to authenticate a client.
        ///   </para>
        ///   <para>
        ///   It must return <see langword="null"/> if the credentials
        ///   are not found.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public Func<IIdentity, NetworkCredential> UserCredentialsFinder
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                return _userCredFinder;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                _userCredFinder = value;
            }
        }

        private bool authenticateClient(HttpListenerContext context)
        {
            var schm = selectAuthenticationScheme(context.Request);

            if (schm == AuthenticationSchemes.Anonymous)
                return true;

            if (schm == AuthenticationSchemes.None)
            {
                var msg = "Authentication not allowed";

                context.SendError(403, msg);

                return false;
            }

            var realm = getRealm();

            if (!context.SetUser(schm, realm, _userCredFinder))
            {
                context.SendAuthenticationChallenge(schm, realm);

                return false;
            }

            return true;
        }

        private HttpListenerAsyncResult beginGetContext(
          AsyncCallback callback,
          object state
        )
        {
            lock (_contextRegistrySync)
            {
                if (!_isListening)
                {
                    var msg = "The method is canceled.";

                    throw new HttpListenerException(995, msg);
                }

                var ares = new HttpListenerAsyncResult(callback, state, _log);

                if (_contextQueue.Count == 0)
                {
                    _waitQueue.Enqueue(ares);

                    return ares;
                }

                var ctx = _contextQueue.Dequeue();

                ares.Complete(ctx, true);

                return ares;
            }
        }

        private void cleanupContextQueue(bool force)
        {
            if (_contextQueue.Count == 0)
                return;

            if (force)
            {
                _contextQueue.Clear();

                return;
            }

            var ctxs = _contextQueue.ToArray();

            _contextQueue.Clear();

            foreach (var ctx in ctxs)
                ctx.SendError(503);
        }

        private void cleanupContextRegistry()
        {
            var cnt = _contextRegistry.Count;

            if (cnt == 0)
                return;

            var ctxs = new HttpListenerContext[cnt];

            lock (_contextRegistrySync)
            {
                _contextRegistry.CopyTo(ctxs, 0);
                _contextRegistry.Clear();
            }

            foreach (var ctx in ctxs)
                ctx.Connection.Close(true);
        }

        private void cleanupWaitQueue(string message)
        {
            if (_waitQueue.Count == 0)
                return;

            var aress = _waitQueue.ToArray();

            _waitQueue.Clear();

            foreach (var ares in aress)
            {
                var ex = new HttpListenerException(995, message);

                ares.Complete(ex);
            }
        }

        private void close(bool force)
        {
            lock (_sync)
            {
                if (_disposed)
                    return;

                lock (_contextRegistrySync)
                {
                    if (!_isListening)
                    {
                        _disposed = true;

                        return;
                    }

                    _isListening = false;
                }

                cleanupContextQueue(force);
                cleanupContextRegistry();

                var msg = "The listener is closed.";

                cleanupWaitQueue(msg);

                EndPointManager.RemoveListener(this);

                _disposed = true;
            }
        }

        private string getRealm()
        {
            var realm = _realm;

            return realm != null && realm.Length > 0 ? realm : _defaultRealm;
        }

        private bool registerContext(HttpListenerContext context)
        {
            if (!_isListening)
                return false;

            lock (_contextRegistrySync)
            {
                if (!_isListening)
                    return false;

                context.Listener = this;

                _contextRegistry.AddLast(context);

                if (_waitQueue.Count == 0)
                {
                    _contextQueue.Enqueue(context);

                    return true;
                }

                var ares = _waitQueue.Dequeue();

                ares.Complete(context, false);

                return true;
            }
        }

        private AuthenticationSchemes selectAuthenticationScheme(
          HttpListenerRequest request
        )
        {
            var selector = _authSchemeSelector;

            if (selector == null)
                return _authSchemes;

            try
            {
                return selector(request);
            }
            catch
            {
                return AuthenticationSchemes.None;
            }
        }

        internal void CheckDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);
        }

        internal bool RegisterContext(HttpListenerContext context)
        {
            if (!authenticateClient(context))
                return false;

            if (!registerContext(context))
            {
                context.SendError(503);

                return false;
            }

            return true;
        }

        internal void UnregisterContext(HttpListenerContext context)
        {
            lock (_contextRegistrySync)
                _contextRegistry.Remove(context);
        }

        /// <summary>
        /// Shuts down the listener immediately.
        /// </summary>
        public void Abort()
        {
            if (_disposed)
                return;

            close(true);
        }

        /// <summary>
        /// Begins getting an incoming request asynchronously.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This asynchronous operation must be ended by calling
        ///   the <see cref="EndGetContext"/> method.
        ///   </para>
        ///   <para>
        ///   Typically, the <see cref="EndGetContext"/> method is called by
        ///   <paramref name="callback"/>.
        ///   </para>
        /// </remarks>
        /// <returns>
        /// An <see cref="IAsyncResult"/> instance that represents the status of
        /// the asynchronous operation.
        /// </returns>
        /// <param name="callback">
        ///   <para>
        ///   An <see cref="AsyncCallback"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the asynchronous operation is
        ///   complete.
        ///   </para>
        /// </param>
        /// <param name="state">
        /// An <see cref="object"/> that specifies a user defined object to pass to
        /// <paramref name="callback"/>.
        /// </param>
        /// <exception cref="HttpListenerException">
        /// This method is canceled.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   This listener has not been started or is currently stopped.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   This listener has no URI prefix on which listens.
        ///   </para>
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public IAsyncResult BeginGetContext(AsyncCallback callback, object state)
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            if (!_isListening)
            {
                var msg = "The listener has not been started.";

                throw new InvalidOperationException(msg);
            }

            if (_prefixes.Count == 0)
            {
                var msg = "The listener has no URI prefix on which listens.";

                throw new InvalidOperationException(msg);
            }

            return beginGetContext(callback, state);
        }

        /// <summary>
        /// Shuts down the listener.
        /// </summary>
        public void Close()
        {
            if (_disposed)
                return;

            close(false);
        }

        /// <summary>
        /// Ends an asynchronous operation to get an incoming request.
        /// </summary>
        /// <remarks>
        /// This method ends an asynchronous operation started by calling
        /// the <see cref="BeginGetContext"/> method.
        /// </remarks>
        /// <returns>
        /// A <see cref="HttpListenerContext"/> that represents a request.
        /// </returns>
        /// <param name="asyncResult">
        /// An <see cref="IAsyncResult"/> instance obtained by calling
        /// the <see cref="BeginGetContext"/> method.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="asyncResult"/> was not obtained by calling
        /// the <see cref="BeginGetContext"/> method.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="asyncResult"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="HttpListenerException">
        /// This method is canceled.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   This listener has not been started or is currently stopped.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   This method was already called for <paramref name="asyncResult"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public HttpListenerContext EndGetContext(IAsyncResult asyncResult)
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            if (!_isListening)
            {
                var msg = "The listener has not been started.";

                throw new InvalidOperationException(msg);
            }

            if (asyncResult == null)
                throw new ArgumentNullException("asyncResult");

            var ares = asyncResult as HttpListenerAsyncResult;

            if (ares == null)
            {
                var msg = "A wrong IAsyncResult instance.";

                throw new ArgumentException(msg, "asyncResult");
            }

            lock (ares.SyncRoot)
            {
                if (ares.EndCalled)
                {
                    var msg = "This IAsyncResult instance cannot be reused.";

                    throw new InvalidOperationException(msg);
                }

                ares.EndCalled = true;
            }

            if (!ares.IsCompleted)
                ares.AsyncWaitHandle.WaitOne();

            return ares.Context;
        }

        /// <summary>
        /// Gets an incoming request.
        /// </summary>
        /// <remarks>
        /// This method waits for an incoming request and returns when
        /// a request is received.
        /// </remarks>
        /// <returns>
        /// A <see cref="HttpListenerContext"/> that represents a request.
        /// </returns>
        /// <exception cref="HttpListenerException">
        /// This method is canceled.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   This listener has not been started or is currently stopped.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   This listener has no URI prefix on which listens.
        ///   </para>
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public HttpListenerContext GetContext()
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            if (!_isListening)
            {
                var msg = "The listener has not been started.";

                throw new InvalidOperationException(msg);
            }

            if (_prefixes.Count == 0)
            {
                var msg = "The listener has no URI prefix on which listens.";

                throw new InvalidOperationException(msg);
            }

            var ares = beginGetContext(null, null);

            ares.EndCalled = true;

            if (!ares.IsCompleted)
                ares.AsyncWaitHandle.WaitOne();

            return ares.Context;
        }

        /// <summary>
        /// Starts receiving incoming requests.
        /// </summary>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public void Start()
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            lock (_sync)
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                lock (_contextRegistrySync)
                {
                    if (_isListening)
                        return;

                    EndPointManager.AddListener(this);

                    _isListening = true;
                }
            }
        }

        /// <summary>
        /// Stops receiving incoming requests.
        /// </summary>
        /// <exception cref="ObjectDisposedException">
        /// This listener has been closed.
        /// </exception>
        public void Stop()
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            lock (_sync)
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                lock (_contextRegistrySync)
                {
                    if (!_isListening)
                        return;

                    _isListening = false;
                }

                cleanupContextQueue(false);
                cleanupContextRegistry();

                var msg = "The listener is stopped.";

                cleanupWaitQueue(msg);

                EndPointManager.RemoveListener(this);
            }
        }

        /// <summary>
        /// Releases all resources used by the listener.
        /// </summary>
        void IDisposable.Dispose()
        {
            if (_disposed)
                return;

            close(true);
        }
    }
    //=======================================================================================
    internal class HttpListenerAsyncResult : IAsyncResult
    {
        private AsyncCallback _callback;
        private bool _completed;
        private bool _completedSynchronously;
        private HttpListenerContext _context;
        private bool _endCalled;
        private Exception _exception;
        private Logger _log;
        private object _state;
        private object _sync;
        private ManualResetEvent _waitHandle;

        internal HttpListenerAsyncResult(
          AsyncCallback callback,
          object state,
          Logger log
        )
        {
            _callback = callback;
            _state = state;
            _log = log;

            _sync = new object();
        }

        internal HttpListenerContext Context
        {
            get
            {
                if (_exception != null)
                    throw _exception;

                return _context;
            }
        }

        internal bool EndCalled
        {
            get
            {
                return _endCalled;
            }

            set
            {
                _endCalled = value;
            }
        }

        internal object SyncRoot
        {
            get
            {
                return _sync;
            }
        }

        public object AsyncState
        {
            get
            {
                return _state;
            }
        }

        public WaitHandle AsyncWaitHandle
        {
            get
            {
                lock (_sync)
                {
                    if (_waitHandle == null)
                        _waitHandle = new ManualResetEvent(_completed);

                    return _waitHandle;
                }
            }
        }

        public bool CompletedSynchronously
        {
            get
            {
                return _completedSynchronously;
            }
        }

        public bool IsCompleted
        {
            get
            {
                lock (_sync)
                    return _completed;
            }
        }

        private void complete()
        {
            lock (_sync)
            {
                _completed = true;

                if (_waitHandle != null)
                    _waitHandle.Set();
            }

            if (_callback == null)
                return;

            ThreadPool.QueueUserWorkItem(
              state => {
                  try
                  {
                      _callback(this);
                  }
                  catch (Exception ex)
                  {
                      _log.Error(ex.Message);
                      _log.Debug(ex.ToString());
                  }
              },
              null
            );
        }

        internal void Complete(Exception exception)
        {
            _exception = exception;

            complete();
        }

        internal void Complete(
          HttpListenerContext context,
          bool completedSynchronously
        )
        {
            _context = context;
            _completedSynchronously = completedSynchronously;

            complete();
        }
    }
    //=====================================================================================
    /// <summary>
    /// Provides the access to the HTTP request and response objects used by
    /// the <see cref="HttpListener"/> class.
    /// </summary>
    /// <remarks>
    /// This class cannot be inherited.
    /// </remarks>
    public sealed class HttpListenerContext
    {
        private HttpConnection _connection;
        private string _errorMessage;
        private int _errorStatusCode;
        private HttpListener _listener;
        private HttpListenerRequest _request;
        private HttpListenerResponse _response;
        private IPrincipal _user;
        private HttpListenerWebSocketContext _websocketContext;

        internal HttpListenerContext(HttpConnection connection)
        {
            _connection = connection;

            _errorStatusCode = 400;
            _request = new HttpListenerRequest(this);
            _response = new HttpListenerResponse(this);
        }

        internal HttpConnection Connection
        {
            get
            {
                return _connection;
            }
        }

        internal string ErrorMessage
        {
            get
            {
                return _errorMessage;
            }

            set
            {
                _errorMessage = value;
            }
        }

        internal int ErrorStatusCode
        {
            get
            {
                return _errorStatusCode;
            }

            set
            {
                _errorStatusCode = value;
            }
        }

        internal bool HasErrorMessage
        {
            get
            {
                return _errorMessage != null;
            }
        }

        internal HttpListener Listener
        {
            get
            {
                return _listener;
            }

            set
            {
                _listener = value;
            }
        }

        /// <summary>
        /// Gets the HTTP request object that represents a client request.
        /// </summary>
        /// <value>
        /// A <see cref="HttpListenerRequest"/> that represents the client request.
        /// </value>
        public HttpListenerRequest Request
        {
            get
            {
                return _request;
            }
        }

        /// <summary>
        /// Gets the HTTP response object used to send a response to the client.
        /// </summary>
        /// <value>
        /// A <see cref="HttpListenerResponse"/> that represents a response to
        /// the client request.
        /// </value>
        public HttpListenerResponse Response
        {
            get
            {
                return _response;
            }
        }

        /// <summary>
        /// Gets the client information.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="IPrincipal"/> instance that represents identity,
        ///   authentication, and security roles for the client.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the client is not authenticated.
        ///   </para>
        /// </value>
        public IPrincipal User
        {
            get
            {
                return _user;
            }
        }

        private static string createErrorContent(
          int statusCode,
          string statusDescription,
          string message
        )
        {
            return message != null && message.Length > 0
                   ? String.Format(
                       "<html><body><h1>{0} {1} ({2})</h1></body></html>",
                       statusCode,
                       statusDescription,
                       message
                     )
                   : String.Format(
                       "<html><body><h1>{0} {1}</h1></body></html>",
                       statusCode,
                       statusDescription
                     );
        }

        internal HttpListenerWebSocketContext GetWebSocketContext(string protocol)
        {
            _websocketContext = new HttpListenerWebSocketContext(this, protocol);

            return _websocketContext;
        }

        internal void SendAuthenticationChallenge(
          AuthenticationSchemes scheme,
          string realm
        )
        {
            _response.StatusCode = 401;

            var val = new AuthenticationChallenge(scheme, realm).ToString();

            _response.Headers.InternalSet("WWW-Authenticate", val, true);

            _response.Close();
        }

        internal void SendError()
        {
            try
            {
                _response.StatusCode = _errorStatusCode;
                _response.ContentType = "text/html";

                var content = createErrorContent(
                                _errorStatusCode,
                                _response.StatusDescription,
                                _errorMessage
                              );

                var enc = Encoding.UTF8;
                var entity = enc.GetBytes(content);

                _response.ContentEncoding = enc;
                _response.ContentLength64 = entity.LongLength;

                _response.Close(entity, true);
            }
            catch
            {
                _connection.Close(true);
            }
        }

        internal void SendError(int statusCode)
        {
            _errorStatusCode = statusCode;

            SendError();
        }

        internal void SendError(int statusCode, string message)
        {
            _errorStatusCode = statusCode;
            _errorMessage = message;

            SendError();
        }

        internal bool SetUser(
          AuthenticationSchemes scheme,
          string realm,
          Func<IIdentity, NetworkCredential> credentialsFinder
        )
        {
            var user = HttpUtility.CreateUser(
                         _request.Headers["Authorization"],
                         scheme,
                         realm,
                         _request.HttpMethod,
                         credentialsFinder
                       );

            if (user == null)
                return false;

            if (!user.Identity.IsAuthenticated)
                return false;

            _user = user;

            return true;
        }

        internal void Unregister()
        {
            if (_listener == null)
                return;

            _listener.UnregisterContext(this);
        }

        /// <summary>
        /// Accepts a WebSocket connection.
        /// </summary>
        /// <returns>
        /// A <see cref="HttpListenerWebSocketContext"/> that represents
        /// the WebSocket handshake request.
        /// </returns>
        /// <param name="protocol">
        ///   <para>
        ///   A <see cref="string"/> that specifies the name of the subprotocol
        ///   supported on the WebSocket connection.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="protocol"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="protocol"/> contains an invalid character.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   This method has already been done.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The client request is not a WebSocket handshake request.
        ///   </para>
        /// </exception>
        public HttpListenerWebSocketContext AcceptWebSocket(string protocol)
        {
            return AcceptWebSocket(protocol, null);
        }

        /// <summary>
        /// Accepts a WebSocket connection with initializing the WebSocket
        /// interface.
        /// </summary>
        /// <returns>
        /// A <see cref="HttpListenerWebSocketContext"/> that represents
        /// the WebSocket handshake request.
        /// </returns>
        /// <param name="protocol">
        ///   <para>
        ///   A <see cref="string"/> that specifies the name of the subprotocol
        ///   supported on the WebSocket connection.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <param name="initializer">
        ///   <para>
        ///   An <see cref="T:System.Action{WebSocket}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when a new WebSocket instance is
        ///   initialized.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="protocol"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="protocol"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="initializer"/> caused an exception.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   This method has already been done.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The client request is not a WebSocket handshake request.
        ///   </para>
        /// </exception>
        public HttpListenerWebSocketContext AcceptWebSocket(
          string protocol,
          Action<WebSocket> initializer
        )
        {
            if (_websocketContext != null)
            {
                var msg = "The method has already been done.";

                throw new InvalidOperationException(msg);
            }

            if (!_request.IsWebSocketRequest)
            {
                var msg = "The request is not a WebSocket handshake request.";

                throw new InvalidOperationException(msg);
            }

            if (protocol != null)
            {
                if (protocol.Length == 0)
                {
                    var msg = "An empty string.";

                    throw new ArgumentException(msg, "protocol");
                }

                if (!protocol.IsToken())
                {
                    var msg = "It contains an invalid character.";

                    throw new ArgumentException(msg, "protocol");
                }
            }

            var ret = GetWebSocketContext(protocol);

            var ws = ret.WebSocket;

            if (initializer != null)
            {
                try
                {
                    initializer(ws);
                }
                catch (Exception ex)
                {
                    if (ws.ReadyState == WebSocketState.New)
                        _websocketContext = null;

                    var msg = "It caused an exception.";

                    throw new ArgumentException(msg, "initializer", ex);
                }
            }

            ws.Accept();

            return ret;
        }
    }
    //==================================================================================
    /// <summary>
    /// The exception that is thrown when an error occurs processing
    /// an HTTP request.
    /// </summary>
    [Serializable]
    public class HttpListenerException : Win32Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HttpListenerException"/>
        /// class with the specified serialized data.
        /// </summary>
        /// <param name="serializationInfo">
        /// A <see cref="SerializationInfo"/> that contains the serialized
        /// object data.
        /// </param>
        /// <param name="streamingContext">
        /// A <see cref="StreamingContext"/> that specifies the source for
        /// the deserialization.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="serializationInfo"/> is <see langword="null"/>.
        /// </exception>
        protected HttpListenerException(
          SerializationInfo serializationInfo,
          StreamingContext streamingContext
        )
          : base(serializationInfo, streamingContext)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpListenerException"/>
        /// class.
        /// </summary>
        public HttpListenerException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpListenerException"/>
        /// class with the specified error code.
        /// </summary>
        /// <param name="errorCode">
        /// An <see cref="int"/> that specifies the error code.
        /// </param>
        public HttpListenerException(int errorCode)
          : base(errorCode)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpListenerException"/>
        /// class with the specified error code and message.
        /// </summary>
        /// <param name="errorCode">
        /// An <see cref="int"/> that specifies the error code.
        /// </param>
        /// <param name="message">
        /// A <see cref="string"/> that specifies the message.
        /// </param>
        public HttpListenerException(int errorCode, string message)
          : base(errorCode, message)
        {
        }

        /// <summary>
        /// Gets the error code that identifies the error that occurred.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An <see cref="int"/> that represents the error code.
        ///   </para>
        ///   <para>
        ///   It is any of the Win32 error codes.
        ///   </para>
        /// </value>
        public override int ErrorCode
        {
            get
            {
                return NativeErrorCode;
            }
        }
    }
    //=============================================================================
    internal sealed class HttpListenerPrefix
    {
        private string _host;
        private bool _isSecure;
        private HttpListener _listener;
        private string _original;
        private string _path;
        private string _port;
        private string _prefix;
        private string _scheme;

        internal HttpListenerPrefix(string uriPrefix, HttpListener listener)
        {
            _original = uriPrefix;
            _listener = listener;

            parse(uriPrefix);
        }

        public string Host
        {
            get
            {
                return _host;
            }
        }

        public bool IsSecure
        {
            get
            {
                return _isSecure;
            }
        }

        public HttpListener Listener
        {
            get
            {
                return _listener;
            }
        }

        public string Original
        {
            get
            {
                return _original;
            }
        }

        public string Path
        {
            get
            {
                return _path;
            }
        }

        public string Port
        {
            get
            {
                return _port;
            }
        }

        public string Scheme
        {
            get
            {
                return _scheme;
            }
        }

        private void parse(string uriPrefix)
        {
            var compType = StringComparison.Ordinal;

            _isSecure = uriPrefix.StartsWith("https", compType);
            _scheme = _isSecure ? "https" : "http";

            var hostStartIdx = uriPrefix.IndexOf(':') + 3;

            var len = uriPrefix.Length;
            var rootIdx = uriPrefix
                          .IndexOf('/', hostStartIdx + 1, len - hostStartIdx - 1);

            var colonIdx = uriPrefix
                           .LastIndexOf(':', rootIdx - 1, rootIdx - hostStartIdx - 1);

            var hasPort = uriPrefix[rootIdx - 1] != ']' && colonIdx > hostStartIdx;

            if (hasPort)
            {
                _host = uriPrefix.Substring(hostStartIdx, colonIdx - hostStartIdx);
                _port = uriPrefix.Substring(colonIdx + 1, rootIdx - colonIdx - 1);
            }
            else
            {
                _host = uriPrefix.Substring(hostStartIdx, rootIdx - hostStartIdx);
                _port = _isSecure ? "443" : "80";
            }

            _path = uriPrefix.Substring(rootIdx);

            var fmt = "{0}://{1}:{2}{3}";

            _prefix = String.Format(fmt, _scheme, _host, _port, _path);
        }

        public static void CheckPrefix(string uriPrefix)
        {
            if (uriPrefix == null)
                throw new ArgumentNullException("uriPrefix");

            var len = uriPrefix.Length;

            if (len == 0)
            {
                var msg = "An empty string.";

                throw new ArgumentException(msg, "uriPrefix");
            }

            var compType = StringComparison.Ordinal;
            var isHttpSchm = uriPrefix.StartsWith("http://", compType)
                             || uriPrefix.StartsWith("https://", compType);

            if (!isHttpSchm)
            {
                var msg = "The scheme is not http or https.";

                throw new ArgumentException(msg, "uriPrefix");
            }

            var endIdx = len - 1;

            if (uriPrefix[endIdx] != '/')
            {
                var msg = "It ends without a forward slash.";

                throw new ArgumentException(msg, "uriPrefix");
            }

            var hostStartIdx = uriPrefix.IndexOf(':') + 3;

            if (hostStartIdx >= endIdx)
            {
                var msg = "No host is specified.";

                throw new ArgumentException(msg, "uriPrefix");
            }

            if (uriPrefix[hostStartIdx] == ':')
            {
                var msg = "No host is specified.";

                throw new ArgumentException(msg, "uriPrefix");
            }

            var rootIdx = uriPrefix.IndexOf('/', hostStartIdx, len - hostStartIdx);

            if (rootIdx == hostStartIdx)
            {
                var msg = "No host is specified.";

                throw new ArgumentException(msg, "uriPrefix");
            }

            if (uriPrefix[rootIdx - 1] == ':')
            {
                var msg = "No port is specified.";

                throw new ArgumentException(msg, "uriPrefix");
            }

            if (rootIdx == endIdx - 1)
            {
                var msg = "No path is specified.";

                throw new ArgumentException(msg, "uriPrefix");
            }
        }

        public override bool Equals(object obj)
        {
            var pref = obj as HttpListenerPrefix;

            return pref != null && _prefix.Equals(pref._prefix);
        }

        public override int GetHashCode()
        {
            return _prefix.GetHashCode();
        }

        public override string ToString()
        {
            return _prefix;
        }
    }
    //=====================================================================================
    /// <summary>
    /// Provides a collection used to store the URI prefixes for a instance of
    /// the <see cref="HttpListener"/> class.
    /// </summary>
    /// <remarks>
    /// The <see cref="HttpListener"/> instance responds to the request which
    /// has a requested URI that the prefixes most closely match.
    /// </remarks>
    public class HttpListenerPrefixCollection : ICollection<string>
    {
        private HttpListener _listener;
        private List<string> _prefixes;

        internal HttpListenerPrefixCollection(HttpListener listener)
        {
            _listener = listener;

            _prefixes = new List<string>();
        }

        /// <summary>
        /// Gets the number of prefixes in the collection.
        /// </summary>
        /// <value>
        /// An <see cref="int"/> that represents the number of prefixes.
        /// </value>
        public int Count
        {
            get
            {
                return _prefixes.Count;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the access to the collection is
        /// read-only.
        /// </summary>
        /// <value>
        /// Always returns <c>false</c>.
        /// </value>
        public bool IsReadOnly
        {
            get
            {
                return false;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the access to the collection is
        /// synchronized.
        /// </summary>
        /// <value>
        /// Always returns <c>false</c>.
        /// </value>
        public bool IsSynchronized
        {
            get
            {
                return false;
            }
        }

        /// <summary>
        /// Adds the specified URI prefix to the collection.
        /// </summary>
        /// <param name="uriPrefix">
        ///   <para>
        ///   A <see cref="string"/> that specifies the URI prefix to add.
        ///   </para>
        ///   <para>
        ///   It must be a well-formed URI prefix with http or https scheme,
        ///   and must end with a forward slash (/).
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="uriPrefix"/> is invalid.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="uriPrefix"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// The <see cref="HttpListener"/> instance associated with this
        /// collection is closed.
        /// </exception>
        public void Add(string uriPrefix)
        {
            _listener.CheckDisposed();

            HttpListenerPrefix.CheckPrefix(uriPrefix);

            if (_prefixes.Contains(uriPrefix))
                return;

            if (_listener.IsListening)
                EndPointManager.AddPrefix(uriPrefix, _listener);

            _prefixes.Add(uriPrefix);
        }

        /// <summary>
        /// Removes all URI prefixes from the collection.
        /// </summary>
        /// <exception cref="ObjectDisposedException">
        /// The <see cref="HttpListener"/> instance associated with this
        /// collection is closed.
        /// </exception>
        public void Clear()
        {
            _listener.CheckDisposed();

            if (_listener.IsListening)
                EndPointManager.RemoveListener(_listener);

            _prefixes.Clear();
        }

        /// <summary>
        /// Returns a value indicating whether the collection contains the
        /// specified URI prefix.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the collection contains the URI prefix; otherwise,
        /// <c>false</c>.
        /// </returns>
        /// <param name="uriPrefix">
        /// A <see cref="string"/> that specifies the URI prefix to test.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="uriPrefix"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// The <see cref="HttpListener"/> instance associated with this
        /// collection is closed.
        /// </exception>
        public bool Contains(string uriPrefix)
        {
            _listener.CheckDisposed();

            if (uriPrefix == null)
                throw new ArgumentNullException("uriPrefix");

            return _prefixes.Contains(uriPrefix);
        }

        /// <summary>
        /// Copies the contents of the collection to the specified array of string.
        /// </summary>
        /// <param name="array">
        /// An array of <see cref="string"/> that specifies the destination of
        /// the URI prefix strings copied from the collection.
        /// </param>
        /// <param name="offset">
        /// An <see cref="int"/> that specifies the zero-based index in
        /// the array at which copying begins.
        /// </param>
        /// <exception cref="ArgumentException">
        /// The space from <paramref name="offset"/> to the end of
        /// <paramref name="array"/> is not enough to copy to.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="array"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="offset"/> is less than zero.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// The <see cref="HttpListener"/> instance associated with this
        /// collection is closed.
        /// </exception>
        public void CopyTo(string[] array, int offset)
        {
            _listener.CheckDisposed();

            _prefixes.CopyTo(array, offset);
        }

        /// <summary>
        /// Gets the enumerator that iterates through the collection.
        /// </summary>
        /// <returns>
        /// An <see cref="T:System.Collections.Generic.IEnumerator{string}"/>
        /// instance that can be used to iterate through the collection.
        /// </returns>
        public IEnumerator<string> GetEnumerator()
        {
            return _prefixes.GetEnumerator();
        }

        /// <summary>
        /// Removes the specified URI prefix from the collection.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the URI prefix is successfully removed; otherwise,
        /// <c>false</c>.
        /// </returns>
        /// <param name="uriPrefix">
        /// A <see cref="string"/> that specifies the URI prefix to remove.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="uriPrefix"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// The <see cref="HttpListener"/> instance associated with this
        /// collection is closed.
        /// </exception>
        public bool Remove(string uriPrefix)
        {
            _listener.CheckDisposed();

            if (uriPrefix == null)
                throw new ArgumentNullException("uriPrefix");

            if (!_prefixes.Contains(uriPrefix))
                return false;

            if (_listener.IsListening)
                EndPointManager.RemovePrefix(uriPrefix, _listener);

            return _prefixes.Remove(uriPrefix);
        }

        /// <summary>
        /// Gets the enumerator that iterates through the collection.
        /// </summary>
        /// <returns>
        /// An <see cref="IEnumerator"/> instance that can be used to iterate
        /// through the collection.
        /// </returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return _prefixes.GetEnumerator();
        }
    }
    //=================================================================================
    /// <summary>
    /// Represents an incoming HTTP request to a <see cref="HttpListener"/>
    /// instance.
    /// </summary>
    /// <remarks>
    /// This class cannot be inherited.
    /// </remarks>
    public sealed class HttpListenerRequest
    {
        private static readonly byte[] _100continue;
        private string[] _acceptTypes;
        private bool _chunked;
        private HttpConnection _connection;
        private Encoding _contentEncoding;
        private long _contentLength;
        private HttpListenerContext _context;
        private CookieCollection _cookies;
        private static readonly Encoding _defaultEncoding;
        private WebHeaderCollection _headers;
        private string _httpMethod;
        private Stream _inputStream;
        private Version _protocolVersion;
        private NameValueCollection _queryString;
        private string _rawUrl;
        private Guid _requestTraceIdentifier;
        private Uri _url;
        private Uri _urlReferrer;
        private bool _urlSet;
        private string _userHostName;
        private string[] _userLanguages;

        static HttpListenerRequest()
        {
            _100continue = Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");
            _defaultEncoding = Encoding.UTF8;
        }

        internal HttpListenerRequest(HttpListenerContext context)
        {
            _context = context;

            _connection = context.Connection;
            _contentLength = -1;
            _headers = new WebHeaderCollection();
            _requestTraceIdentifier = Guid.NewGuid();
        }

        /// <summary>
        /// Gets the media types that are acceptable for the client.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An array of <see cref="string"/> that contains the names of
        ///   the media types specified in the value of the Accept header.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the header is not present.
        ///   </para>
        /// </value>
        public string[] AcceptTypes
        {
            get
            {
                var val = _headers["Accept"];

                if (val == null)
                    return null;

                if (_acceptTypes == null)
                {
                    _acceptTypes = val
                                   .SplitHeaderValue(',')
                                   .TrimEach()
                                   .ToList()
                                   .ToArray();
                }

                return _acceptTypes;
            }
        }

        /// <summary>
        /// Gets an error code that identifies a problem with the certificate
        /// provided by the client.
        /// </summary>
        /// <value>
        /// An <see cref="int"/> that represents an error code.
        /// </value>
        /// <exception cref="NotSupportedException">
        /// This property is not supported.
        /// </exception>
        public int ClientCertificateError
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the encoding for the entity body data included in the request.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="Encoding"/> converted from the charset value of the
        ///   Content-Type header.
        ///   </para>
        ///   <para>
        ///   <see cref="Encoding.UTF8"/> if the charset value is not available.
        ///   </para>
        /// </value>
        public Encoding ContentEncoding
        {
            get
            {
                if (_contentEncoding == null)
                    _contentEncoding = getContentEncoding();

                return _contentEncoding;
            }
        }

        /// <summary>
        /// Gets the length in bytes of the entity body data included in the
        /// request.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="long"/> converted from the value of the Content-Length
        ///   header.
        ///   </para>
        ///   <para>
        ///   -1 if the header is not present.
        ///   </para>
        /// </value>
        public long ContentLength64
        {
            get
            {
                return _contentLength;
            }
        }

        /// <summary>
        /// Gets the media type of the entity body data included in the request.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the value of the Content-Type
        ///   header.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the header is not present.
        ///   </para>
        /// </value>
        public string ContentType
        {
            get
            {
                return _headers["Content-Type"];
            }
        }

        /// <summary>
        /// Gets the HTTP cookies included in the request.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="CookieCollection"/> that contains the cookies.
        ///   </para>
        ///   <para>
        ///   An empty collection if not included.
        ///   </para>
        /// </value>
        public CookieCollection Cookies
        {
            get
            {
                if (_cookies == null)
                    _cookies = _headers.GetCookies(false);

                return _cookies;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the request has the entity body data.
        /// </summary>
        /// <value>
        /// <c>true</c> if the request has the entity body data; otherwise,
        /// <c>false</c>.
        /// </value>
        public bool HasEntityBody
        {
            get
            {
                return _contentLength > 0 || _chunked;
            }
        }

        /// <summary>
        /// Gets the HTTP headers included in the request.
        /// </summary>
        /// <value>
        /// A <see cref="NameValueCollection"/> that contains the headers.
        /// </value>
        public NameValueCollection Headers
        {
            get
            {
                return _headers;
            }
        }

        /// <summary>
        /// Gets the HTTP method specified by the client.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the HTTP method specified in
        /// the request line.
        /// </value>
        public string HttpMethod
        {
            get
            {
                return _httpMethod;
            }
        }

        /// <summary>
        /// Gets a stream that contains the entity body data included in
        /// the request.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="Stream"/> that contains the entity body data.
        ///   </para>
        ///   <para>
        ///   <see cref="Stream.Null"/> if the entity body data is not available.
        ///   </para>
        /// </value>
        public Stream InputStream
        {
            get
            {
                if (_inputStream == null)
                {
                    _inputStream = _contentLength > 0 || _chunked
                                   ? _connection
                                     .GetRequestStream(_contentLength, _chunked)
                                   : Stream.Null;
                }

                return _inputStream;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the client is authenticated.
        /// </summary>
        /// <value>
        /// <c>true</c> if the client is authenticated; otherwise, <c>false</c>.
        /// </value>
        public bool IsAuthenticated
        {
            get
            {
                return _context.User != null;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the request is sent from the
        /// local computer.
        /// </summary>
        /// <value>
        /// <c>true</c> if the request is sent from the same computer as
        /// the server; otherwise, <c>false</c>.
        /// </value>
        public bool IsLocal
        {
            get
            {
                return _connection.IsLocal;
            }
        }

        /// <summary>
        /// Gets a value indicating whether a secure connection is used to send
        /// the request.
        /// </summary>
        /// <value>
        /// <c>true</c> if the connection is secure; otherwise, <c>false</c>.
        /// </value>
        public bool IsSecureConnection
        {
            get
            {
                return _connection.IsSecure;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the request is a WebSocket handshake
        /// request.
        /// </summary>
        /// <value>
        /// <c>true</c> if the request is a WebSocket handshake request; otherwise,
        /// <c>false</c>.
        /// </value>
        public bool IsWebSocketRequest
        {
            get
            {
                return _httpMethod == "GET" && _headers.Upgrades("websocket");
            }
        }

        /// <summary>
        /// Gets a value indicating whether a persistent connection is requested.
        /// </summary>
        /// <value>
        /// <c>true</c> if the request specifies that the connection is kept open;
        /// otherwise, <c>false</c>.
        /// </value>
        public bool KeepAlive
        {
            get
            {
                return _headers.KeepsAlive(_protocolVersion);
            }
        }

        /// <summary>
        /// Gets the endpoint to which the request is sent.
        /// </summary>
        /// <value>
        /// A <see cref="System.Net.IPEndPoint"/> that represents the server
        /// IP address and port number.
        /// </value>
        public System.Net.IPEndPoint LocalEndPoint
        {
            get
            {
                return _connection.LocalEndPoint;
            }
        }

        /// <summary>
        /// Gets the HTTP version specified by the client.
        /// </summary>
        /// <value>
        /// A <see cref="Version"/> that represents the HTTP version specified in
        /// the request line.
        /// </value>
        public Version ProtocolVersion
        {
            get
            {
                return _protocolVersion;
            }
        }

        /// <summary>
        /// Gets the query string included in the request.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="NameValueCollection"/> that contains the query
        ///   parameters.
        ///   </para>
        ///   <para>
        ///   Each query parameter is decoded in UTF-8.
        ///   </para>
        ///   <para>
        ///   An empty collection if not included.
        ///   </para>
        /// </value>
        public NameValueCollection QueryString
        {
            get
            {
                if (_queryString == null)
                {
                    var url = Url;
                    var query = url != null ? url.Query : null;

                    _queryString = QueryStringCollection.Parse(query, _defaultEncoding);
                }

                return _queryString;
            }
        }

        /// <summary>
        /// Gets the raw URL specified by the client.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the request target specified in
        /// the request line.
        /// </value>
        public string RawUrl
        {
            get
            {
                return _rawUrl;
            }
        }

        /// <summary>
        /// Gets the endpoint from which the request is sent.
        /// </summary>
        /// <value>
        /// A <see cref="System.Net.IPEndPoint"/> that represents the client
        /// IP address and port number.
        /// </value>
        public System.Net.IPEndPoint RemoteEndPoint
        {
            get
            {
                return _connection.RemoteEndPoint;
            }
        }

        /// <summary>
        /// Gets the trace identifier of the request.
        /// </summary>
        /// <value>
        /// A <see cref="Guid"/> that represents the trace identifier.
        /// </value>
        public Guid RequestTraceIdentifier
        {
            get
            {
                return _requestTraceIdentifier;
            }
        }

        /// <summary>
        /// Gets the URL requested by the client.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="Uri"/> that represents the URL parsed from the request.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the URL cannot be parsed.
        ///   </para>
        /// </value>
        public Uri Url
        {
            get
            {
                if (!_urlSet)
                {
                    _url = HttpUtility
                           .CreateRequestUrl(
                             _rawUrl,
                             _userHostName,
                             IsWebSocketRequest,
                             IsSecureConnection
                           );

                    _urlSet = true;
                }

                return _url;
            }
        }

        /// <summary>
        /// Gets the URI of the resource from which the requested URL was obtained.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="Uri"/> that represents the value of the Referer header.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the header value is not available.
        ///   </para>
        /// </value>
        public Uri UrlReferrer
        {
            get
            {
                var val = _headers["Referer"];

                if (val == null)
                    return null;

                if (_urlReferrer == null)
                    _urlReferrer = val.ToUri();

                return _urlReferrer;
            }
        }

        /// <summary>
        /// Gets the user agent from which the request is originated.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the value of the User-Agent
        ///   header.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the header is not present.
        ///   </para>
        /// </value>
        public string UserAgent
        {
            get
            {
                return _headers["User-Agent"];
            }
        }

        /// <summary>
        /// Gets the IP address and port number to which the request is sent.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the server IP address and
        /// port number.
        /// </value>
        public string UserHostAddress
        {
            get
            {
                return _connection.LocalEndPoint.ToString();
            }
        }

        /// <summary>
        /// Gets the server host name requested by the client.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the value of the Host header.
        ///   </para>
        ///   <para>
        ///   It includes the port number if provided.
        ///   </para>
        /// </value>
        public string UserHostName
        {
            get
            {
                return _userHostName;
            }
        }

        /// <summary>
        /// Gets the natural languages that are acceptable for the client.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An array of <see cref="string"/> that contains the names of the
        ///   natural languages specified in the value of the Accept-Language
        ///   header.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the header is not present.
        ///   </para>
        /// </value>
        public string[] UserLanguages
        {
            get
            {
                var val = _headers["Accept-Language"];

                if (val == null)
                    return null;

                if (_userLanguages == null)
                    _userLanguages = val.Split(',').TrimEach().ToList().ToArray();

                return _userLanguages;
            }
        }

        private Encoding getContentEncoding()
        {
            var val = _headers["Content-Type"];

            if (val == null)
                return _defaultEncoding;

            Encoding ret;

            return HttpUtility.TryGetEncoding(val, out ret)
                   ? ret
                   : _defaultEncoding;
        }

        internal void AddHeader(string headerField)
        {
            var start = headerField[0];

            if (start == ' ' || start == '\t')
            {
                _context.ErrorMessage = "Invalid header field";

                return;
            }

            var colon = headerField.IndexOf(':');

            if (colon < 1)
            {
                _context.ErrorMessage = "Invalid header field";

                return;
            }

            var name = headerField.Substring(0, colon).Trim();

            if (name.Length == 0 || !name.IsToken())
            {
                _context.ErrorMessage = "Invalid header name";

                return;
            }

            var val = colon < headerField.Length - 1
                      ? headerField.Substring(colon + 1).Trim()
                      : String.Empty;

            _headers.InternalSet(name, val, false);

            var lower = name.ToLower(CultureInfo.InvariantCulture);

            if (lower == "host")
            {
                if (_userHostName != null)
                {
                    _context.ErrorMessage = "Invalid Host header";

                    return;
                }

                if (val.Length == 0)
                {
                    _context.ErrorMessage = "Invalid Host header";

                    return;
                }

                _userHostName = val;

                return;
            }

            if (lower == "content-length")
            {
                if (_contentLength > -1)
                {
                    _context.ErrorMessage = "Invalid Content-Length header";

                    return;
                }

                long len;

                if (!Int64.TryParse(val, out len))
                {
                    _context.ErrorMessage = "Invalid Content-Length header";

                    return;
                }

                if (len < 0)
                {
                    _context.ErrorMessage = "Invalid Content-Length header";

                    return;
                }

                _contentLength = len;

                return;
            }
        }

        internal void FinishInitialization()
        {
            if (_userHostName == null)
            {
                _context.ErrorMessage = "Host header required";

                return;
            }

            var transferEnc = _headers["Transfer-Encoding"];

            if (transferEnc != null)
            {
                var compType = StringComparison.OrdinalIgnoreCase;

                if (!transferEnc.Equals("chunked", compType))
                {
                    _context.ErrorStatusCode = 501;
                    _context.ErrorMessage = "Invalid Transfer-Encoding header";

                    return;
                }

                _chunked = true;
            }

            if (_httpMethod == "POST" || _httpMethod == "PUT")
            {
                if (_contentLength == -1 && !_chunked)
                {
                    _context.ErrorStatusCode = 411;
                    _context.ErrorMessage = "Content-Length header required";

                    return;
                }

                if (_contentLength == 0 && !_chunked)
                {
                    _context.ErrorStatusCode = 411;
                    _context.ErrorMessage = "Invalid Content-Length header";

                    return;
                }
            }

            var expect = _headers["Expect"];

            if (expect != null)
            {
                var compType = StringComparison.OrdinalIgnoreCase;

                if (!expect.Equals("100-continue", compType))
                {
                    _context.ErrorStatusCode = 417;
                    _context.ErrorMessage = "Invalid Expect header";

                    return;
                }

                var output = _connection.GetResponseStream();

                output.InternalWrite(_100continue, 0, _100continue.Length);
            }
        }

        internal bool FlushInput()
        {
            var input = InputStream;

            if (input == Stream.Null)
                return true;

            var len = 2048;

            if (_contentLength > 0 && _contentLength < len)
                len = (int)_contentLength;

            var buff = new byte[len];

            while (true)
            {
                try
                {
                    var ares = input.BeginRead(buff, 0, len, null, null);

                    if (!ares.IsCompleted)
                    {
                        var timeout = 100;

                        if (!ares.AsyncWaitHandle.WaitOne(timeout))
                            return false;
                    }

                    if (input.EndRead(ares) <= 0)
                        return true;
                }
                catch
                {
                    return false;
                }
            }
        }

        internal bool IsUpgradeRequest(string protocol)
        {
            return _headers.Upgrades(protocol);
        }

        internal void SetRequestLine(string requestLine)
        {
            var parts = requestLine.Split(new[] { ' ' }, 3);

            if (parts.Length < 3)
            {
                _context.ErrorMessage = "Invalid request line (parts)";

                return;
            }

            var method = parts[0];

            if (method.Length == 0)
            {
                _context.ErrorMessage = "Invalid request line (method)";

                return;
            }

            if (!method.IsHttpMethod())
            {
                _context.ErrorStatusCode = 501;
                _context.ErrorMessage = "Invalid request line (method)";

                return;
            }

            var target = parts[1];

            if (target.Length == 0)
            {
                _context.ErrorMessage = "Invalid request line (target)";

                return;
            }

            var rawVer = parts[2];

            if (rawVer.Length != 8)
            {
                _context.ErrorMessage = "Invalid request line (version)";

                return;
            }

            if (!rawVer.StartsWith("HTTP/", StringComparison.Ordinal))
            {
                _context.ErrorMessage = "Invalid request line (version)";

                return;
            }

            Version ver;

            if (!rawVer.Substring(5).TryCreateVersion(out ver))
            {
                _context.ErrorMessage = "Invalid request line (version)";

                return;
            }

            if (ver != HttpVersion.Version11)
            {
                _context.ErrorStatusCode = 505;
                _context.ErrorMessage = "Invalid request line (version)";

                return;
            }

            _httpMethod = method;
            _rawUrl = target;
            _protocolVersion = ver;
        }

        /// <summary>
        /// Begins getting the certificate provided by the client asynchronously.
        /// </summary>
        /// <returns>
        /// An <see cref="IAsyncResult"/> instance that represents the status of
        /// the asynchronous operation.
        /// </returns>
        /// <param name="requestCallback">
        ///   <para>
        ///   An <see cref="AsyncCallback"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the asynchronous operation is
        ///   complete.
        ///   </para>
        /// </param>
        /// <param name="state">
        /// An <see cref="object"/> that specifies a user defined object to pass to
        /// <paramref name="requestCallback"/>.
        /// </param>
        /// <exception cref="NotSupportedException">
        /// This method is not supported.
        /// </exception>
        public IAsyncResult BeginGetClientCertificate(
          AsyncCallback requestCallback,
          object state
        )
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Ends an asynchronous operation to get the certificate provided by
        /// the client.
        /// </summary>
        /// <returns>
        /// A <see cref="X509Certificate2"/> that represents an X.509 certificate
        /// provided by the client.
        /// </returns>
        /// <param name="asyncResult">
        /// An <see cref="IAsyncResult"/> instance obtained by calling
        /// the <see cref="BeginGetClientCertificate"/> method.
        /// </param>
        /// <exception cref="NotSupportedException">
        /// This method is not supported.
        /// </exception>
        public X509Certificate2 EndGetClientCertificate(IAsyncResult asyncResult)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Gets the certificate provided by the client.
        /// </summary>
        /// <returns>
        /// A <see cref="X509Certificate2"/> that represents an X.509 certificate
        /// provided by the client.
        /// </returns>
        /// <exception cref="NotSupportedException">
        /// This method is not supported.
        /// </exception>
        public X509Certificate2 GetClientCertificate()
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Returns a string that represents the current instance.
        /// </summary>
        /// <returns>
        /// A <see cref="string"/> that contains the request line and headers
        /// included in the request.
        /// </returns>
        public override string ToString()
        {
            var buff = new StringBuilder(64);

            var fmt = "{0} {1} HTTP/{2}\r\n";
            var headers = _headers.ToString();

            buff
            .AppendFormat(fmt, _httpMethod, _rawUrl, _protocolVersion)
            .Append(headers);

            return buff.ToString();
        }
    }
    //================================================================================
    /// <summary>
    /// Represents an HTTP response to an HTTP request received by
    /// a <see cref="HttpListener"/> instance.
    /// </summary>
    /// <remarks>
    /// This class cannot be inherited.
    /// </remarks>
    public sealed class HttpListenerResponse : IDisposable
    {
        private bool _closeConnection;
        private Encoding _contentEncoding;
        private long _contentLength;
        private string _contentType;
        private HttpListenerContext _context;
        private CookieCollection _cookies;
        private static readonly string _defaultProductName;
        private bool _disposed;
        private WebHeaderCollection _headers;
        private bool _headersSent;
        private bool _keepAlive;
        private ResponseStream _outputStream;
        private Uri _redirectLocation;
        private bool _sendChunked;
        private int _statusCode;
        private string _statusDescription;
        private Version _version;

        static HttpListenerResponse()
        {
            _defaultProductName = "websocket-sharp/1.0";
        }

        internal HttpListenerResponse(HttpListenerContext context)
        {
            _context = context;

            _keepAlive = true;
            _statusCode = 200;
            _statusDescription = "OK";
            _version = HttpVersion.Version11;
        }

        internal bool CloseConnection
        {
            get
            {
                return _closeConnection;
            }

            set
            {
                _closeConnection = value;
            }
        }

        internal WebHeaderCollection FullHeaders
        {
            get
            {
                var headers = new WebHeaderCollection(HttpHeaderType.Response, true);

                if (_headers != null)
                    headers.Add(_headers);

                if (_contentType != null)
                {
                    var val = createContentTypeHeaderText(_contentType, _contentEncoding);

                    headers.InternalSet("Content-Type", val, true);
                }

                if (headers["Server"] == null)
                    headers.InternalSet("Server", _defaultProductName, true);

                if (headers["Date"] == null)
                {
                    var val = DateTime.UtcNow.ToString("r", CultureInfo.InvariantCulture);

                    headers.InternalSet("Date", val, true);
                }

                if (_sendChunked)
                {
                    headers.InternalSet("Transfer-Encoding", "chunked", true);
                }
                else
                {
                    var val = _contentLength.ToString(CultureInfo.InvariantCulture);

                    headers.InternalSet("Content-Length", val, true);
                }

                /*
                 * Apache forces closing the connection for these status codes:
                 * - 400 Bad Request
                 * - 408 Request Timeout
                 * - 411 Length Required
                 * - 413 Request Entity Too Large
                 * - 414 Request-Uri Too Long
                 * - 500 Internal Server Error
                 * - 503 Service Unavailable
                 */

                var reuses = _context.Connection.Reuses;
                var closeConn = !_context.Request.KeepAlive
                                || !_keepAlive
                                || reuses >= 100
                                || _statusCode == 400
                                || _statusCode == 408
                                || _statusCode == 411
                                || _statusCode == 413
                                || _statusCode == 414
                                || _statusCode == 500
                                || _statusCode == 503;

                if (closeConn)
                {
                    headers.InternalSet("Connection", "close", true);
                }
                else
                {
                    var fmt = "timeout=15,max={0}";
                    var max = 100 - reuses;
                    var val = String.Format(fmt, max);

                    headers.InternalSet("Keep-Alive", val, true);
                }

                if (_redirectLocation != null)
                    headers.InternalSet("Location", _redirectLocation.AbsoluteUri, true);

                if (_cookies != null)
                {
                    foreach (var cookie in _cookies)
                    {
                        var val = cookie.ToResponseString();

                        headers.InternalSet("Set-Cookie", val, true);
                    }
                }

                return headers;
            }
        }

        internal bool HeadersSent
        {
            get
            {
                return _headersSent;
            }

            set
            {
                _headersSent = value;
            }
        }

        internal string ObjectName
        {
            get
            {
                return GetType().ToString();
            }
        }

        internal string StatusLine
        {
            get
            {
                var fmt = "HTTP/{0} {1} {2}\r\n";

                return String.Format(fmt, _version, _statusCode, _statusDescription);
            }
        }

        /// <summary>
        /// Gets or sets the encoding for the entity body data included in
        /// the response.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="Encoding"/> that represents the encoding for
        ///   the entity body data.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if no encoding is specified.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The response is already being sent.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This instance is closed.
        /// </exception>
        public Encoding ContentEncoding
        {
            get
            {
                return _contentEncoding;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                if (_headersSent)
                {
                    var msg = "The response is already being sent.";

                    throw new InvalidOperationException(msg);
                }

                _contentEncoding = value;
            }
        }

        /// <summary>
        /// Gets or sets the number of bytes in the entity body data included in
        /// the response.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="long"/> that represents the number of bytes in
        ///   the entity body data.
        ///   </para>
        ///   <para>
        ///   It is used for the value of the Content-Length header.
        ///   </para>
        ///   <para>
        ///   The default value is zero.
        ///   </para>
        /// </value>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The value specified for a set operation is less than zero.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The response is already being sent.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This instance is closed.
        /// </exception>
        public long ContentLength64
        {
            get
            {
                return _contentLength;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                if (_headersSent)
                {
                    var msg = "The response is already being sent.";

                    throw new InvalidOperationException(msg);
                }

                if (value < 0)
                {
                    var msg = "Less than zero.";

                    throw new ArgumentOutOfRangeException(msg, "value");
                }

                _contentLength = value;
            }
        }

        /// <summary>
        /// Gets or sets the media type of the entity body included in
        /// the response.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the media type of
        ///   the entity body.
        ///   </para>
        ///   <para>
        ///   It is used for the value of the Content-Type header.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if no media type is specified.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   The value specified for a set operation is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The value specified for a set operation contains
        ///   an invalid character.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The response is already being sent.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This instance is closed.
        /// </exception>
        public string ContentType
        {
            get
            {
                return _contentType;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                if (_headersSent)
                {
                    var msg = "The response is already being sent.";

                    throw new InvalidOperationException(msg);
                }

                if (value == null)
                {
                    _contentType = null;

                    return;
                }

                if (value.Length == 0)
                    throw new ArgumentException("An empty string.", "value");

                if (!isValidForContentType(value))
                {
                    var msg = "It contains an invalid character.";

                    throw new ArgumentException(msg, "value");
                }

                _contentType = value;
            }
        }

        /// <summary>
        /// Gets or sets the collection of the HTTP cookies sent with the response.
        /// </summary>
        /// <value>
        /// A <see cref="CookieCollection"/> that contains the cookies sent with
        /// the response.
        /// </value>
        public CookieCollection Cookies
        {
            get
            {
                if (_cookies == null)
                    _cookies = new CookieCollection();

                return _cookies;
            }

            set
            {
                _cookies = value;
            }
        }

        /// <summary>
        /// Gets or sets the collection of the HTTP headers sent to the client.
        /// </summary>
        /// <value>
        /// A <see cref="WebHeaderCollection"/> that contains the headers sent to
        /// the client.
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The value specified for a set operation is not valid for a response.
        /// </exception>
        public WebHeaderCollection Headers
        {
            get
            {
                if (_headers == null)
                    _headers = new WebHeaderCollection(HttpHeaderType.Response, false);

                return _headers;
            }

            set
            {
                if (value == null)
                {
                    _headers = null;

                    return;
                }

                if (value.State != HttpHeaderType.Response)
                {
                    var msg = "The value is not valid for a response.";

                    throw new InvalidOperationException(msg);
                }

                _headers = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the server requests
        /// a persistent connection.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the server requests a persistent connection;
        ///   otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>true</c>.
        ///   </para>
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The response is already being sent.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This instance is closed.
        /// </exception>
        public bool KeepAlive
        {
            get
            {
                return _keepAlive;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                if (_headersSent)
                {
                    var msg = "The response is already being sent.";

                    throw new InvalidOperationException(msg);
                }

                _keepAlive = value;
            }
        }

        /// <summary>
        /// Gets a stream instance to which the entity body data can be written.
        /// </summary>
        /// <value>
        /// A <see cref="Stream"/> instance to which the entity body data can be
        /// written.
        /// </value>
        /// <exception cref="ObjectDisposedException">
        /// This instance is closed.
        /// </exception>
        public Stream OutputStream
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                if (_outputStream == null)
                    _outputStream = _context.Connection.GetResponseStream();

                return _outputStream;
            }
        }

        /// <summary>
        /// Gets the HTTP version used for the response.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="Version"/> that represents the HTTP version used for
        ///   the response.
        ///   </para>
        ///   <para>
        ///   Always returns same as 1.1.
        ///   </para>
        /// </value>
        public Version ProtocolVersion
        {
            get
            {
                return _version;
            }
        }

        /// <summary>
        /// Gets or sets the URL to which the client is redirected to locate
        /// a requested resource.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the absolute URL for
        ///   the redirect location.
        ///   </para>
        ///   <para>
        ///   It is used for the value of the Location header.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if no redirect location is specified.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   The value specified for a set operation is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The value specified for a set operation is not an absolute URL.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The response is already being sent.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This instance is closed.
        /// </exception>
        public string RedirectLocation
        {
            get
            {
                return _redirectLocation != null
                       ? _redirectLocation.OriginalString
                       : null;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                if (_headersSent)
                {
                    var msg = "The response is already being sent.";

                    throw new InvalidOperationException(msg);
                }

                if (value == null)
                {
                    _redirectLocation = null;

                    return;
                }

                if (value.Length == 0)
                    throw new ArgumentException("An empty string.", "value");

                Uri uri;

                if (!Uri.TryCreate(value, UriKind.Absolute, out uri))
                {
                    var msg = "Not an absolute URL.";

                    throw new ArgumentException(msg, "value");
                }

                _redirectLocation = uri;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the response uses the chunked
        /// transfer encoding.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the response uses the chunked transfer encoding;
        ///   otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The response is already being sent.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This instance is closed.
        /// </exception>
        public bool SendChunked
        {
            get
            {
                return _sendChunked;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                if (_headersSent)
                {
                    var msg = "The response is already being sent.";

                    throw new InvalidOperationException(msg);
                }

                _sendChunked = value;
            }
        }

        /// <summary>
        /// Gets or sets the HTTP status code returned to the client.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An <see cref="int"/> that represents the HTTP status code for
        ///   the response to the request.
        ///   </para>
        ///   <para>
        ///   The default value is 200. It indicates that the request has
        ///   succeeded.
        ///   </para>
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The response is already being sent.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This instance is closed.
        /// </exception>
        /// <exception cref="System.Net.ProtocolViolationException">
        ///   <para>
        ///   The value specified for a set operation is invalid.
        ///   </para>
        ///   <para>
        ///   Valid values are between 100 and 999 inclusive.
        ///   </para>
        /// </exception>
        public int StatusCode
        {
            get
            {
                return _statusCode;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                if (_headersSent)
                {
                    var msg = "The response is already being sent.";

                    throw new InvalidOperationException(msg);
                }

                if (value < 100 || value > 999)
                {
                    var msg = "A value is not between 100 and 999 inclusive.";

                    throw new System.Net.ProtocolViolationException(msg);
                }

                _statusCode = value;
                _statusDescription = value.GetStatusDescription();
            }
        }

        /// <summary>
        /// Gets or sets the description of the HTTP status code returned to
        /// the client.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the description of
        ///   the HTTP status code for the response to the request.
        ///   </para>
        ///   <para>
        ///   The default value is
        ///   the <see href="http://tools.ietf.org/html/rfc2616#section-10">
        ///   RFC 2616</see> description for the <see cref="StatusCode"/>
        ///   property value.
        ///   </para>
        ///   <para>
        ///   An empty string if an RFC 2616 description does not exist.
        ///   </para>
        /// </value>
        /// <exception cref="ArgumentException">
        /// The value specified for a set operation contains an invalid character.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// The value specified for a set operation is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The response is already being sent.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This instance is closed.
        /// </exception>
        public string StatusDescription
        {
            get
            {
                return _statusDescription;
            }

            set
            {
                if (_disposed)
                    throw new ObjectDisposedException(ObjectName);

                if (_headersSent)
                {
                    var msg = "The response is already being sent.";

                    throw new InvalidOperationException(msg);
                }

                if (value == null)
                    throw new ArgumentNullException("value");

                if (value.Length == 0)
                {
                    _statusDescription = _statusCode.GetStatusDescription();

                    return;
                }

                if (!isValidForStatusDescription(value))
                {
                    var msg = "It contains an invalid character.";

                    throw new ArgumentException(msg, "value");
                }

                _statusDescription = value;
            }
        }

        private bool canSetCookie(Cookie cookie)
        {
            var res = findCookie(cookie).ToList();

            if (res.Count == 0)
                return true;

            var ver = cookie.Version;

            foreach (var c in res)
            {
                if (c.Version == ver)
                    return true;
            }

            return false;
        }

        private void close(bool force)
        {
            _disposed = true;

            _context.Connection.Close(force);
        }

        private void close(byte[] responseEntity, int bufferLength, bool willBlock)
        {
            if (willBlock)
            {
                OutputStream.WriteBytes(responseEntity, bufferLength);
                close(false);

                return;
            }

            OutputStream.WriteBytesAsync(
              responseEntity,
              bufferLength,
              () => close(false),
              null
            );
        }

        private static string createContentTypeHeaderText(
          string value,
          Encoding encoding
        )
        {
            if (value.Contains("charset="))
                return value;

            if (encoding == null)
                return value;

            var fmt = "{0}; charset={1}";

            return String.Format(fmt, value, encoding.WebName);
        }

        private IEnumerable<Cookie> findCookie(Cookie cookie)
        {
            if (_cookies == null || _cookies.Count == 0)
                yield break;

            foreach (var c in _cookies)
            {
                if (c.EqualsWithoutValueAndVersion(cookie))
                    yield return c;
            }
        }

        private static bool isValidForContentType(string value)
        {
            foreach (var c in value)
            {
                if (c < 0x20)
                    return false;

                if (c > 0x7e)
                    return false;

                if ("()<>@:\\[]?{}".IndexOf(c) > -1)
                    return false;
            }

            return true;
        }

        private static bool isValidForStatusDescription(string value)
        {
            foreach (var c in value)
            {
                if (c < 0x20)
                    return false;

                if (c > 0x7e)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Closes the connection to the client without sending a response.
        /// </summary>
        public void Abort()
        {
            if (_disposed)
                return;

            close(true);
        }

        /// <summary>
        /// Appends an HTTP cookie to the cookies sent with the response.
        /// </summary>
        /// <param name="cookie">
        /// A <see cref="Cookie"/> to append.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="cookie"/> is <see langword="null"/>.
        /// </exception>
        public void AppendCookie(Cookie cookie)
        {
            Cookies.Add(cookie);
        }

        /// <summary>
        /// Appends an HTTP header with the specified name and value to
        /// the headers for the response.
        /// </summary>
        /// <param name="name">
        /// A <see cref="string"/> that specifies the name of the header to
        /// append.
        /// </param>
        /// <param name="value">
        /// A <see cref="string"/> that specifies the value of the header to
        /// append.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="name"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> is a string of spaces.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="value"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> is a restricted header name.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="name"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of <paramref name="value"/> is greater than 65,535
        /// characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The current headers do not allow the header.
        /// </exception>
        public void AppendHeader(string name, string value)
        {
            Headers.Add(name, value);
        }

        /// <summary>
        /// Sends the response to the client and releases the resources used by
        /// this instance.
        /// </summary>
        public void Close()
        {
            if (_disposed)
                return;

            close(false);
        }

        /// <summary>
        /// Sends the response with the specified entity body data to the client
        /// and releases the resources used by this instance.
        /// </summary>
        /// <param name="responseEntity">
        /// An array of <see cref="byte"/> that contains the entity body data.
        /// </param>
        /// <param name="willBlock">
        /// A <see cref="bool"/>: <c>true</c> if this method blocks execution while
        /// flushing the stream to the client; otherwise, <c>false</c>.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="responseEntity"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This instance is closed.
        /// </exception>
        public void Close(byte[] responseEntity, bool willBlock)
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            if (responseEntity == null)
                throw new ArgumentNullException("responseEntity");

            var len = responseEntity.LongLength;

            if (len > Int32.MaxValue)
            {
                close(responseEntity, 1024, willBlock);

                return;
            }

            var stream = OutputStream;

            if (willBlock)
            {
                stream.Write(responseEntity, 0, (int)len);
                close(false);

                return;
            }

            stream.BeginWrite(
              responseEntity,
              0,
              (int)len,
              ar => {
                  stream.EndWrite(ar);
                  close(false);
              },
              null
            );
        }

        /// <summary>
        /// Copies some properties from the specified response instance to
        /// this instance.
        /// </summary>
        /// <param name="templateResponse">
        /// A <see cref="HttpListenerResponse"/> to copy.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="templateResponse"/> is <see langword="null"/>.
        /// </exception>
        public void CopyFrom(HttpListenerResponse templateResponse)
        {
            if (templateResponse == null)
                throw new ArgumentNullException("templateResponse");

            var headers = templateResponse._headers;

            if (headers != null)
            {
                if (_headers != null)
                    _headers.Clear();

                Headers.Add(headers);
            }
            else
            {
                _headers = null;
            }

            _contentLength = templateResponse._contentLength;
            _statusCode = templateResponse._statusCode;
            _statusDescription = templateResponse._statusDescription;
            _keepAlive = templateResponse._keepAlive;
            _version = templateResponse._version;
        }

        /// <summary>
        /// Configures the response to redirect the client's request to
        /// the specified URL.
        /// </summary>
        /// <remarks>
        /// This method sets the <see cref="RedirectLocation"/> property to
        /// <paramref name="url"/>, the <see cref="StatusCode"/> property to
        /// 302, and the <see cref="StatusDescription"/> property to "Found".
        /// </remarks>
        /// <param name="url">
        /// A <see cref="string"/> that specifies the absolute URL to which
        /// the client is redirected to locate a requested resource.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="url"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="url"/> is not an absolute URL.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="url"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The response is already being sent.
        /// </exception>
        /// <exception cref="ObjectDisposedException">
        /// This instance is closed.
        /// </exception>
        public void Redirect(string url)
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            if (_headersSent)
            {
                var msg = "The response is already being sent.";

                throw new InvalidOperationException(msg);
            }

            if (url == null)
                throw new ArgumentNullException("url");

            if (url.Length == 0)
                throw new ArgumentException("An empty string.", "url");

            Uri uri;

            if (!Uri.TryCreate(url, UriKind.Absolute, out uri))
            {
                var msg = "Not an absolute URL.";

                throw new ArgumentException(msg, "url");
            }

            _redirectLocation = uri;
            _statusCode = 302;
            _statusDescription = "Found";
        }

        /// <summary>
        /// Adds or updates an HTTP cookie in the cookies sent with the response.
        /// </summary>
        /// <param name="cookie">
        /// A <see cref="Cookie"/> to set.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="cookie"/> already exists in the cookies but
        /// it cannot be updated.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="cookie"/> is <see langword="null"/>.
        /// </exception>
        public void SetCookie(Cookie cookie)
        {
            if (cookie == null)
                throw new ArgumentNullException("cookie");

            if (!canSetCookie(cookie))
            {
                var msg = "It cannot be updated.";

                throw new ArgumentException(msg, "cookie");
            }

            Cookies.Add(cookie);
        }

        /// <summary>
        /// Adds or updates an HTTP header with the specified name and value in
        /// the headers for the response.
        /// </summary>
        /// <param name="name">
        /// A <see cref="string"/> that specifies the name of the header to set.
        /// </param>
        /// <param name="value">
        /// A <see cref="string"/> that specifies the value of the header to set.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="name"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> is a string of spaces.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="value"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> is a restricted header name.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="name"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of <paramref name="value"/> is greater than 65,535
        /// characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The current headers do not allow the header.
        /// </exception>
        public void SetHeader(string name, string value)
        {
            Headers.Set(name, value);
        }

        /// <summary>
        /// Releases all resources used by this instance.
        /// </summary>
        void IDisposable.Dispose()
        {
            if (_disposed)
                return;

            close(true);
        }
    }
    //=========================================================================
    /// <summary>
    /// Indicates the HTTP header that may be specified in a client request.
    /// </summary>
    /// <remarks>
    /// The headers of this enumeration are defined in
    /// <see href="http://tools.ietf.org/html/rfc2616#section-14">RFC 2616</see> or
    /// <see href="http://tools.ietf.org/html/rfc6455#section-11.3">RFC 6455</see>.
    /// </remarks>
    public enum HttpRequestHeader
    {
        /// <summary>
        /// Indicates the Cache-Control header.
        /// </summary>
        CacheControl,
        /// <summary>
        /// Indicates the Connection header.
        /// </summary>
        Connection,
        /// <summary>
        /// Indicates the Date header.
        /// </summary>
        Date,
        /// <summary>
        /// Indicates the Keep-Alive header.
        /// </summary>
        KeepAlive,
        /// <summary>
        /// Indicates the Pragma header.
        /// </summary>
        Pragma,
        /// <summary>
        /// Indicates the Trailer header.
        /// </summary>
        Trailer,
        /// <summary>
        /// Indicates the Transfer-Encoding header.
        /// </summary>
        TransferEncoding,
        /// <summary>
        /// Indicates the Upgrade header.
        /// </summary>
        Upgrade,
        /// <summary>
        /// Indicates the Via header.
        /// </summary>
        Via,
        /// <summary>
        /// Indicates the Warning header.
        /// </summary>
        Warning,
        /// <summary>
        /// Indicates the Allow header.
        /// </summary>
        Allow,
        /// <summary>
        /// Indicates the Content-Length header.
        /// </summary>
        ContentLength,
        /// <summary>
        /// Indicates the Content-Type header.
        /// </summary>
        ContentType,
        /// <summary>
        /// Indicates the Content-Encoding header.
        /// </summary>
        ContentEncoding,
        /// <summary>
        /// Indicates the Content-Language header.
        /// </summary>
        ContentLanguage,
        /// <summary>
        /// Indicates the Content-Location header.
        /// </summary>
        ContentLocation,
        /// <summary>
        /// Indicates the Content-MD5 header.
        /// </summary>
        ContentMd5,
        /// <summary>
        /// Indicates the Content-Range header.
        /// </summary>
        ContentRange,
        /// <summary>
        /// Indicates the Expires header.
        /// </summary>
        Expires,
        /// <summary>
        /// Indicates the Last-Modified header.
        /// </summary>
        LastModified,
        /// <summary>
        /// Indicates the Accept header.
        /// </summary>
        Accept,
        /// <summary>
        /// Indicates the Accept-Charset header.
        /// </summary>
        AcceptCharset,
        /// <summary>
        /// Indicates the Accept-Encoding header.
        /// </summary>
        AcceptEncoding,
        /// <summary>
        /// Indicates the Accept-Language header.
        /// </summary>
        AcceptLanguage,
        /// <summary>
        /// Indicates the Authorization header.
        /// </summary>
        Authorization,
        /// <summary>
        /// Indicates the Cookie header.
        /// </summary>
        Cookie,
        /// <summary>
        /// Indicates the Expect header.
        /// </summary>
        Expect,
        /// <summary>
        /// Indicates the From header.
        /// </summary>
        From,
        /// <summary>
        /// Indicates the Host header.
        /// </summary>
        Host,
        /// <summary>
        /// Indicates the If-Match header.
        /// </summary>
        IfMatch,
        /// <summary>
        /// Indicates the If-Modified-Since header.
        /// </summary>
        IfModifiedSince,
        /// <summary>
        /// Indicates the If-None-Match header.
        /// </summary>
        IfNoneMatch,
        /// <summary>
        /// Indicates the If-Range header.
        /// </summary>
        IfRange,
        /// <summary>
        /// Indicates the If-Unmodified-Since header.
        /// </summary>
        IfUnmodifiedSince,
        /// <summary>
        /// Indicates the Max-Forwards header.
        /// </summary>
        MaxForwards,
        /// <summary>
        /// Indicates the Proxy-Authorization header.
        /// </summary>
        ProxyAuthorization,
        /// <summary>
        /// Indicates the Referer header.
        /// </summary>
        Referer,
        /// <summary>
        /// Indicates the Range header.
        /// </summary>
        Range,
        /// <summary>
        /// Indicates the TE header.
        /// </summary>
        Te,
        /// <summary>
        /// Indicates the Translate header.
        /// </summary>
        Translate,
        /// <summary>
        /// Indicates the User-Agent header.
        /// </summary>
        UserAgent,
        /// <summary>
        /// Indicates the Sec-WebSocket-Key header.
        /// </summary>
        SecWebSocketKey,
        /// <summary>
        /// Indicates the Sec-WebSocket-Extensions header.
        /// </summary>
        SecWebSocketExtensions,
        /// <summary>
        /// Indicates the Sec-WebSocket-Protocol header.
        /// </summary>
        SecWebSocketProtocol,
        /// <summary>
        /// Indicates the Sec-WebSocket-Version header.
        /// </summary>
        SecWebSocketVersion
    }
    //=================================================================================
    /// <summary>
    /// Indicates the HTTP header that can be specified in a server response.
    /// </summary>
    /// <remarks>
    /// The headers of this enumeration are defined in
    /// <see href="http://tools.ietf.org/html/rfc2616#section-14">RFC 2616</see> or
    /// <see href="http://tools.ietf.org/html/rfc6455#section-11.3">RFC 6455</see>.
    /// </remarks>
    public enum HttpResponseHeader
    {
        /// <summary>
        /// Indicates the Cache-Control header.
        /// </summary>
        CacheControl,
        /// <summary>
        /// Indicates the Connection header.
        /// </summary>
        Connection,
        /// <summary>
        /// Indicates the Date header.
        /// </summary>
        Date,
        /// <summary>
        /// Indicates the Keep-Alive header.
        /// </summary>
        KeepAlive,
        /// <summary>
        /// Indicates the Pragma header.
        /// </summary>
        Pragma,
        /// <summary>
        /// Indicates the Trailer header.
        /// </summary>
        Trailer,
        /// <summary>
        /// Indicates the Transfer-Encoding header.
        /// </summary>
        TransferEncoding,
        /// <summary>
        /// Indicates the Upgrade header.
        /// </summary>
        Upgrade,
        /// <summary>
        /// Indicates the Via header.
        /// </summary>
        Via,
        /// <summary>
        /// Indicates the Warning header.
        /// </summary>
        Warning,
        /// <summary>
        /// Indicates the Allow header.
        /// </summary>
        Allow,
        /// <summary>
        /// Indicates the Content-Length header.
        /// </summary>
        ContentLength,
        /// <summary>
        /// Indicates the Content-Type header.
        /// </summary>
        ContentType,
        /// <summary>
        /// Indicates the Content-Encoding header.
        /// </summary>
        ContentEncoding,
        /// <summary>
        /// Indicates the Content-Language header.
        /// </summary>
        ContentLanguage,
        /// <summary>
        /// Indicates the Content-Location header.
        /// </summary>
        ContentLocation,
        /// <summary>
        /// Indicates the Content-MD5 header.
        /// </summary>
        ContentMd5,
        /// <summary>
        /// Indicates the Content-Range header.
        /// </summary>
        ContentRange,
        /// <summary>
        /// Indicates the Expires header.
        /// </summary>
        Expires,
        /// <summary>
        /// Indicates the Last-Modified header.
        /// </summary>
        LastModified,
        /// <summary>
        /// Indicates the Accept-Ranges header.
        /// </summary>
        AcceptRanges,
        /// <summary>
        /// Indicates the Age header.
        /// </summary>
        Age,
        /// <summary>
        /// Indicates the ETag header.
        /// </summary>
        ETag,
        /// <summary>
        /// Indicates the Location header.
        /// </summary>
        Location,
        /// <summary>
        /// Indicates the Proxy-Authenticate header.
        /// </summary>
        ProxyAuthenticate,
        /// <summary>
        /// Indicates the Retry-After header.
        /// </summary>
        RetryAfter,
        /// <summary>
        /// Indicates the Server header.
        /// </summary>
        Server,
        /// <summary>
        /// Indicates the Set-Cookie header.
        /// </summary>
        SetCookie,
        /// <summary>
        /// Indicates the Vary header.
        /// </summary>
        Vary,
        /// <summary>
        /// Indicates the WWW-Authenticate header.
        /// </summary>
        WwwAuthenticate,
        /// <summary>
        /// Indicates the Sec-WebSocket-Extensions header.
        /// </summary>
        SecWebSocketExtensions,
        /// <summary>
        /// Indicates the Sec-WebSocket-Accept header.
        /// </summary>
        SecWebSocketAccept,
        /// <summary>
        /// Indicates the Sec-WebSocket-Protocol header.
        /// </summary>
        SecWebSocketProtocol,
        /// <summary>
        /// Indicates the Sec-WebSocket-Version header.
        /// </summary>
        SecWebSocketVersion
    }
    //============================================================================
    /// <summary>
    /// Indicates the HTTP status code that can be specified in a server response.
    /// </summary>
    /// <remarks>
    /// The values of this enumeration are defined in
    /// <see href="http://tools.ietf.org/html/rfc2616#section-10">RFC 2616</see>.
    /// </remarks>
    public enum HttpStatusCode
    {
        /// <summary>
        /// Equivalent to status code 100. Indicates that the client should continue
        /// with its request.
        /// </summary>
        Continue = 100,
        /// <summary>
        /// Equivalent to status code 101. Indicates that the server is switching
        /// the HTTP version or protocol on the connection.
        /// </summary>
        SwitchingProtocols = 101,
        /// <summary>
        /// Equivalent to status code 200. Indicates that the client's request has
        /// succeeded.
        /// </summary>
        OK = 200,
        /// <summary>
        /// Equivalent to status code 201. Indicates that the client's request has
        /// been fulfilled and resulted in a new resource being created.
        /// </summary>
        Created = 201,
        /// <summary>
        /// Equivalent to status code 202. Indicates that the client's request has
        /// been accepted for processing, but the processing has not been completed.
        /// </summary>
        Accepted = 202,
        /// <summary>
        /// Equivalent to status code 203. Indicates that the returned metainformation
        /// is from a local or a third-party copy instead of the origin server.
        /// </summary>
        NonAuthoritativeInformation = 203,
        /// <summary>
        /// Equivalent to status code 204. Indicates that the server has fulfilled
        /// the client's request but does not need to return an entity-body.
        /// </summary>
        NoContent = 204,
        /// <summary>
        /// Equivalent to status code 205. Indicates that the server has fulfilled
        /// the client's request, and the user agent should reset the document view
        /// which caused the request to be sent.
        /// </summary>
        ResetContent = 205,
        /// <summary>
        /// Equivalent to status code 206. Indicates that the server has fulfilled
        /// the partial GET request for the resource.
        /// </summary>
        PartialContent = 206,
        /// <summary>
        ///   <para>
        ///   Equivalent to status code 300. Indicates that the requested resource
        ///   corresponds to any of multiple representations.
        ///   </para>
        ///   <para>
        ///   MultipleChoices is a synonym for Ambiguous.
        ///   </para>
        /// </summary>
        MultipleChoices = 300,
        /// <summary>
        ///   <para>
        ///   Equivalent to status code 300. Indicates that the requested resource
        ///   corresponds to any of multiple representations.
        ///   </para>
        ///   <para>
        ///   Ambiguous is a synonym for MultipleChoices.
        ///   </para>
        /// </summary>
        Ambiguous = 300,
        /// <summary>
        ///   <para>
        ///   Equivalent to status code 301. Indicates that the requested resource
        ///   has been assigned a new permanent URI and any future references to
        ///   this resource should use one of the returned URIs.
        ///   </para>
        ///   <para>
        ///   MovedPermanently is a synonym for Moved.
        ///   </para>
        /// </summary>
        MovedPermanently = 301,
        /// <summary>
        ///   <para>
        ///   Equivalent to status code 301. Indicates that the requested resource
        ///   has been assigned a new permanent URI and any future references to
        ///   this resource should use one of the returned URIs.
        ///   </para>
        ///   <para>
        ///   Moved is a synonym for MovedPermanently.
        ///   </para>
        /// </summary>
        Moved = 301,
        /// <summary>
        ///   <para>
        ///   Equivalent to status code 302. Indicates that the requested resource
        ///   is located temporarily under a different URI.
        ///   </para>
        ///   <para>
        ///   Found is a synonym for Redirect.
        ///   </para>
        /// </summary>
        Found = 302,
        /// <summary>
        ///   <para>
        ///   Equivalent to status code 302. Indicates that the requested resource
        ///   is located temporarily under a different URI.
        ///   </para>
        ///   <para>
        ///   Redirect is a synonym for Found.
        ///   </para>
        /// </summary>
        Redirect = 302,
        /// <summary>
        ///   <para>
        ///   Equivalent to status code 303. Indicates that the response to
        ///   the request can be found under a different URI and should be
        ///   retrieved using a GET method on that resource.
        ///   </para>
        ///   <para>
        ///   SeeOther is a synonym for RedirectMethod.
        ///   </para>
        /// </summary>
        SeeOther = 303,
        /// <summary>
        ///   <para>
        ///   Equivalent to status code 303. Indicates that the response to
        ///   the request can be found under a different URI and should be
        ///   retrieved using a GET method on that resource.
        ///   </para>
        ///   <para>
        ///   RedirectMethod is a synonym for SeeOther.
        ///   </para>
        /// </summary>
        RedirectMethod = 303,
        /// <summary>
        /// Equivalent to status code 304. Indicates that the client has performed
        /// a conditional GET request and access is allowed, but the document has
        /// not been modified.
        /// </summary>
        NotModified = 304,
        /// <summary>
        /// Equivalent to status code 305. Indicates that the requested resource
        /// must be accessed through the proxy given by the Location field.
        /// </summary>
        UseProxy = 305,
        /// <summary>
        /// Equivalent to status code 306. This status code was used in a previous
        /// version of the specification, is no longer used, and is reserved for
        /// future use.
        /// </summary>
        Unused = 306,
        /// <summary>
        ///   <para>
        ///   Equivalent to status code 307. Indicates that the requested resource
        ///   is located temporarily under a different URI.
        ///   </para>
        ///   <para>
        ///   TemporaryRedirect is a synonym for RedirectKeepVerb.
        ///   </para>
        /// </summary>
        TemporaryRedirect = 307,
        /// <summary>
        ///   <para>
        ///   Equivalent to status code 307. Indicates that the requested resource
        ///   is located temporarily under a different URI.
        ///   </para>
        ///   <para>
        ///   RedirectKeepVerb is a synonym for TemporaryRedirect.
        ///   </para>
        /// </summary>
        RedirectKeepVerb = 307,
        /// <summary>
        /// Equivalent to status code 400. Indicates that the client's request could
        /// not be understood by the server due to malformed syntax.
        /// </summary>
        BadRequest = 400,
        /// <summary>
        /// Equivalent to status code 401. Indicates that the client's request
        /// requires user authentication.
        /// </summary>
        Unauthorized = 401,
        /// <summary>
        /// Equivalent to status code 402. This status code is reserved for future
        /// use.
        /// </summary>
        PaymentRequired = 402,
        /// <summary>
        /// Equivalent to status code 403. Indicates that the server understood
        /// the client's request but is refusing to fulfill it.
        /// </summary>
        Forbidden = 403,
        /// <summary>
        /// Equivalent to status code 404. Indicates that the server has not found
        /// anything matching the request URI.
        /// </summary>
        NotFound = 404,
        /// <summary>
        /// Equivalent to status code 405. Indicates that the method specified
        /// in the request line is not allowed for the resource identified by
        /// the request URI.
        /// </summary>
        MethodNotAllowed = 405,
        /// <summary>
        /// Equivalent to status code 406. Indicates that the server does not
        /// have the appropriate resource to respond to the Accept headers in
        /// the client's request.
        /// </summary>
        NotAcceptable = 406,
        /// <summary>
        /// Equivalent to status code 407. Indicates that the client must first
        /// authenticate itself with the proxy.
        /// </summary>
        ProxyAuthenticationRequired = 407,
        /// <summary>
        /// Equivalent to status code 408. Indicates that the client did not produce
        /// a request within the time that the server was prepared to wait.
        /// </summary>
        RequestTimeout = 408,
        /// <summary>
        /// Equivalent to status code 409. Indicates that the client's request could
        /// not be completed due to a conflict on the server.
        /// </summary>
        Conflict = 409,
        /// <summary>
        /// Equivalent to status code 410. Indicates that the requested resource is
        /// no longer available at the server and no forwarding address is known.
        /// </summary>
        Gone = 410,
        /// <summary>
        /// Equivalent to status code 411. Indicates that the server refuses to
        /// accept the client's request without a defined Content-Length.
        /// </summary>
        LengthRequired = 411,
        /// <summary>
        /// Equivalent to status code 412. Indicates that the precondition given in
        /// one or more of the request headers evaluated to false when it was tested
        /// on the server.
        /// </summary>
        PreconditionFailed = 412,
        /// <summary>
        /// Equivalent to status code 413. Indicates that the entity of the client's
        /// request is larger than the server is willing or able to process.
        /// </summary>
        RequestEntityTooLarge = 413,
        /// <summary>
        /// Equivalent to status code 414. Indicates that the request URI is longer
        /// than the server is willing to interpret.
        /// </summary>
        RequestUriTooLong = 414,
        /// <summary>
        /// Equivalent to status code 415. Indicates that the entity of the client's
        /// request is in a format not supported by the requested resource for the
        /// requested method.
        /// </summary>
        UnsupportedMediaType = 415,
        /// <summary>
        /// Equivalent to status code 416. Indicates that none of the range
        /// specifier values in a Range request header overlap the current
        /// extent of the selected resource.
        /// </summary>
        RequestedRangeNotSatisfiable = 416,
        /// <summary>
        /// Equivalent to status code 417. Indicates that the expectation given in
        /// an Expect request header could not be met by the server.
        /// </summary>
        ExpectationFailed = 417,
        /// <summary>
        /// Equivalent to status code 500. Indicates that the server encountered
        /// an unexpected condition which prevented it from fulfilling the client's
        /// request.
        /// </summary>
        InternalServerError = 500,
        /// <summary>
        /// Equivalent to status code 501. Indicates that the server does not
        /// support the functionality required to fulfill the client's request.
        /// </summary>
        NotImplemented = 501,
        /// <summary>
        /// Equivalent to status code 502. Indicates that a gateway or proxy server
        /// received an invalid response from the upstream server.
        /// </summary>
        BadGateway = 502,
        /// <summary>
        /// Equivalent to status code 503. Indicates that the server is currently
        /// unable to handle the client's request due to a temporary overloading
        /// or maintenance of the server.
        /// </summary>
        ServiceUnavailable = 503,
        /// <summary>
        /// Equivalent to status code 504. Indicates that a gateway or proxy server
        /// did not receive a timely response from the upstream server or some other
        /// auxiliary server.
        /// </summary>
        GatewayTimeout = 504,
        /// <summary>
        /// Equivalent to status code 505. Indicates that the server does not
        /// support the HTTP version used in the client's request.
        /// </summary>
        HttpVersionNotSupported = 505,
    }
    //=========================================================================================
    internal class HttpStreamAsyncResult : IAsyncResult
    {
        private byte[] _buffer;
        private AsyncCallback _callback;
        private bool _completed;
        private int _count;
        private Exception _exception;
        private int _offset;
        private object _state;
        private object _sync;
        private int _syncRead;
        private ManualResetEvent _waitHandle;

        internal HttpStreamAsyncResult(AsyncCallback callback, object state)
        {
            _callback = callback;
            _state = state;

            _sync = new object();
        }

        internal byte[] Buffer
        {
            get
            {
                return _buffer;
            }

            set
            {
                _buffer = value;
            }
        }

        internal int Count
        {
            get
            {
                return _count;
            }

            set
            {
                _count = value;
            }
        }

        internal Exception Exception
        {
            get
            {
                return _exception;
            }
        }

        internal bool HasException
        {
            get
            {
                return _exception != null;
            }
        }

        internal int Offset
        {
            get
            {
                return _offset;
            }

            set
            {
                _offset = value;
            }
        }

        internal int SyncRead
        {
            get
            {
                return _syncRead;
            }

            set
            {
                _syncRead = value;
            }
        }

        public object AsyncState
        {
            get
            {
                return _state;
            }
        }

        public WaitHandle AsyncWaitHandle
        {
            get
            {
                lock (_sync)
                {
                    if (_waitHandle == null)
                        _waitHandle = new ManualResetEvent(_completed);

                    return _waitHandle;
                }
            }
        }

        public bool CompletedSynchronously
        {
            get
            {
                return _syncRead == _count;
            }
        }

        public bool IsCompleted
        {
            get
            {
                lock (_sync)
                    return _completed;
            }
        }

        internal void Complete()
        {
            lock (_sync)
            {
                if (_completed)
                    return;

                _completed = true;

                if (_waitHandle != null)
                    _waitHandle.Set();

                if (_callback != null)
                    _callback.BeginInvoke(this, ar => _callback.EndInvoke(ar), null);
            }
        }

        internal void Complete(Exception exception)
        {
            lock (_sync)
            {
                if (_completed)
                    return;

                _completed = true;
                _exception = exception;

                if (_waitHandle != null)
                    _waitHandle.Set();

                if (_callback != null)
                    _callback.BeginInvoke(this, ar => _callback.EndInvoke(ar), null);
            }
        }
    }
    //======================================================================================
    internal static class HttpUtility
    {
        private static Dictionary<string, char> _entities;
        private static char[] _hexChars;
        private static object _sync;

        static HttpUtility()
        {
            _hexChars = "0123456789ABCDEF".ToCharArray();
            _sync = new object();
        }

        private static Dictionary<string, char> getEntities()
        {
            lock (_sync)
            {
                if (_entities == null)
                    initEntities();

                return _entities;
            }
        }

        private static int getNumber(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';

            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;

            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;

            return -1;
        }

        private static int getNumber(byte[] bytes, int offset, int count)
        {
            var ret = 0;

            var end = offset + count - 1;

            for (var i = offset; i <= end; i++)
            {
                var c = (char)bytes[i];
                var n = getNumber(c);

                if (n == -1)
                    return -1;

                ret = (ret << 4) + n;
            }

            return ret;
        }

        private static int getNumber(string s, int offset, int count)
        {
            var ret = 0;

            var end = offset + count - 1;

            for (var i = offset; i <= end; i++)
            {
                var c = s[i];
                var n = getNumber(c);

                if (n == -1)
                    return -1;

                ret = (ret << 4) + n;
            }

            return ret;
        }

        private static string htmlDecode(string s)
        {
            var buff = new StringBuilder();

            // 0: None
            // 1: Right after '&'
            // 2: Between '&' and ';' but no NCR
            // 3: '#' found after '&' and getting numbers
            // 4: 'x' found after '#' and getting numbers
            var state = 0;

            var reference = new StringBuilder();
            var num = 0;

            foreach (var c in s)
            {
                if (state == 0)
                {
                    if (c == '&')
                    {
                        reference.Append('&');

                        state = 1;

                        continue;
                    }

                    buff.Append(c);

                    continue;
                }

                if (c == '&')
                {
                    buff.Append(reference.ToString());

                    reference.Length = 0;

                    reference.Append('&');

                    state = 1;

                    continue;
                }

                reference.Append(c);

                if (state == 1)
                {
                    if (c == ';')
                    {
                        buff.Append(reference.ToString());

                        reference.Length = 0;
                        state = 0;

                        continue;
                    }

                    num = 0;
                    state = c == '#' ? 3 : 2;

                    continue;
                }

                if (state == 2)
                {
                    if (c == ';')
                    {
                        var entity = reference.ToString();
                        var name = entity.Substring(1, entity.Length - 2);

                        var entities = getEntities();

                        if (entities.ContainsKey(name))
                            buff.Append(entities[name]);
                        else
                            buff.Append(entity);

                        reference.Length = 0;
                        state = 0;

                        continue;
                    }

                    continue;
                }

                if (state == 3)
                {
                    if (c == ';')
                    {
                        if (reference.Length > 3 && num < 65536)
                            buff.Append((char)num);
                        else
                            buff.Append(reference.ToString());

                        reference.Length = 0;
                        state = 0;

                        continue;
                    }

                    if (c == 'x')
                    {
                        state = reference.Length == 3 ? 4 : 2;

                        continue;
                    }

                    if (!isNumeric(c))
                    {
                        state = 2;

                        continue;
                    }

                    num = num * 10 + (c - '0');

                    continue;
                }

                if (state == 4)
                {
                    if (c == ';')
                    {
                        if (reference.Length > 4 && num < 65536)
                            buff.Append((char)num);
                        else
                            buff.Append(reference.ToString());

                        reference.Length = 0;
                        state = 0;

                        continue;
                    }

                    var n = getNumber(c);

                    if (n == -1)
                    {
                        state = 2;

                        continue;
                    }

                    num = (num << 4) + n;
                }
            }

            if (reference.Length > 0)
                buff.Append(reference.ToString());

            return buff.ToString();
        }

        /// <summary>
        /// Converts the specified string to an HTML-encoded string.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This method starts encoding with a NCR from the character code 160
        ///   but does not stop at the character code 255.
        ///   </para>
        ///   <para>
        ///   One reason is the unicode characters &#65308; and &#65310; that
        ///   look like &lt; and &gt;.
        ///   </para>
        /// </remarks>
        /// <returns>
        /// A <see cref="string"/> that represents an encoded string.
        /// </returns>
        /// <param name="s">
        /// A <see cref="string"/> to encode.
        /// </param>
        /// <param name="minimal">
        /// A <see cref="bool"/>: <c>true</c> if encodes without a NCR;
        /// otherwise, <c>false</c>.
        /// </param>
        private static string htmlEncode(string s, bool minimal)
        {
            var buff = new StringBuilder();

            foreach (var c in s)
            {
                if (c == '"')
                {
                    buff.Append("&quot;");

                    continue;
                }

                if (c == '&')
                {
                    buff.Append("&amp;");

                    continue;
                }

                if (c == '<')
                {
                    buff.Append("&lt;");

                    continue;
                }

                if (c == '>')
                {
                    buff.Append("&gt;");

                    continue;
                }

                if (c > 159)
                {
                    if (!minimal)
                    {
                        var val = String.Format("&#{0};", (int)c);

                        buff.Append(val);

                        continue;
                    }
                }

                buff.Append(c);
            }

            return buff.ToString();
        }

        /// <summary>
        /// Initializes the _entities field.
        /// </summary>
        /// <remarks>
        /// This method builds a dictionary of HTML character entity references.
        /// This dictionary comes from the HTML 4.01 W3C recommendation.
        /// </remarks>
        private static void initEntities()
        {
            _entities = new Dictionary<string, char>();

            _entities.Add("nbsp", '\u00A0');
            _entities.Add("iexcl", '\u00A1');
            _entities.Add("cent", '\u00A2');
            _entities.Add("pound", '\u00A3');
            _entities.Add("curren", '\u00A4');
            _entities.Add("yen", '\u00A5');
            _entities.Add("brvbar", '\u00A6');
            _entities.Add("sect", '\u00A7');
            _entities.Add("uml", '\u00A8');
            _entities.Add("copy", '\u00A9');
            _entities.Add("ordf", '\u00AA');
            _entities.Add("laquo", '\u00AB');
            _entities.Add("not", '\u00AC');
            _entities.Add("shy", '\u00AD');
            _entities.Add("reg", '\u00AE');
            _entities.Add("macr", '\u00AF');
            _entities.Add("deg", '\u00B0');
            _entities.Add("plusmn", '\u00B1');
            _entities.Add("sup2", '\u00B2');
            _entities.Add("sup3", '\u00B3');
            _entities.Add("acute", '\u00B4');
            _entities.Add("micro", '\u00B5');
            _entities.Add("para", '\u00B6');
            _entities.Add("middot", '\u00B7');
            _entities.Add("cedil", '\u00B8');
            _entities.Add("sup1", '\u00B9');
            _entities.Add("ordm", '\u00BA');
            _entities.Add("raquo", '\u00BB');
            _entities.Add("frac14", '\u00BC');
            _entities.Add("frac12", '\u00BD');
            _entities.Add("frac34", '\u00BE');
            _entities.Add("iquest", '\u00BF');
            _entities.Add("Agrave", '\u00C0');
            _entities.Add("Aacute", '\u00C1');
            _entities.Add("Acirc", '\u00C2');
            _entities.Add("Atilde", '\u00C3');
            _entities.Add("Auml", '\u00C4');
            _entities.Add("Aring", '\u00C5');
            _entities.Add("AElig", '\u00C6');
            _entities.Add("Ccedil", '\u00C7');
            _entities.Add("Egrave", '\u00C8');
            _entities.Add("Eacute", '\u00C9');
            _entities.Add("Ecirc", '\u00CA');
            _entities.Add("Euml", '\u00CB');
            _entities.Add("Igrave", '\u00CC');
            _entities.Add("Iacute", '\u00CD');
            _entities.Add("Icirc", '\u00CE');
            _entities.Add("Iuml", '\u00CF');
            _entities.Add("ETH", '\u00D0');
            _entities.Add("Ntilde", '\u00D1');
            _entities.Add("Ograve", '\u00D2');
            _entities.Add("Oacute", '\u00D3');
            _entities.Add("Ocirc", '\u00D4');
            _entities.Add("Otilde", '\u00D5');
            _entities.Add("Ouml", '\u00D6');
            _entities.Add("times", '\u00D7');
            _entities.Add("Oslash", '\u00D8');
            _entities.Add("Ugrave", '\u00D9');
            _entities.Add("Uacute", '\u00DA');
            _entities.Add("Ucirc", '\u00DB');
            _entities.Add("Uuml", '\u00DC');
            _entities.Add("Yacute", '\u00DD');
            _entities.Add("THORN", '\u00DE');
            _entities.Add("szlig", '\u00DF');
            _entities.Add("agrave", '\u00E0');
            _entities.Add("aacute", '\u00E1');
            _entities.Add("acirc", '\u00E2');
            _entities.Add("atilde", '\u00E3');
            _entities.Add("auml", '\u00E4');
            _entities.Add("aring", '\u00E5');
            _entities.Add("aelig", '\u00E6');
            _entities.Add("ccedil", '\u00E7');
            _entities.Add("egrave", '\u00E8');
            _entities.Add("eacute", '\u00E9');
            _entities.Add("ecirc", '\u00EA');
            _entities.Add("euml", '\u00EB');
            _entities.Add("igrave", '\u00EC');
            _entities.Add("iacute", '\u00ED');
            _entities.Add("icirc", '\u00EE');
            _entities.Add("iuml", '\u00EF');
            _entities.Add("eth", '\u00F0');
            _entities.Add("ntilde", '\u00F1');
            _entities.Add("ograve", '\u00F2');
            _entities.Add("oacute", '\u00F3');
            _entities.Add("ocirc", '\u00F4');
            _entities.Add("otilde", '\u00F5');
            _entities.Add("ouml", '\u00F6');
            _entities.Add("divide", '\u00F7');
            _entities.Add("oslash", '\u00F8');
            _entities.Add("ugrave", '\u00F9');
            _entities.Add("uacute", '\u00FA');
            _entities.Add("ucirc", '\u00FB');
            _entities.Add("uuml", '\u00FC');
            _entities.Add("yacute", '\u00FD');
            _entities.Add("thorn", '\u00FE');
            _entities.Add("yuml", '\u00FF');
            _entities.Add("fnof", '\u0192');
            _entities.Add("Alpha", '\u0391');
            _entities.Add("Beta", '\u0392');
            _entities.Add("Gamma", '\u0393');
            _entities.Add("Delta", '\u0394');
            _entities.Add("Epsilon", '\u0395');
            _entities.Add("Zeta", '\u0396');
            _entities.Add("Eta", '\u0397');
            _entities.Add("Theta", '\u0398');
            _entities.Add("Iota", '\u0399');
            _entities.Add("Kappa", '\u039A');
            _entities.Add("Lambda", '\u039B');
            _entities.Add("Mu", '\u039C');
            _entities.Add("Nu", '\u039D');
            _entities.Add("Xi", '\u039E');
            _entities.Add("Omicron", '\u039F');
            _entities.Add("Pi", '\u03A0');
            _entities.Add("Rho", '\u03A1');
            _entities.Add("Sigma", '\u03A3');
            _entities.Add("Tau", '\u03A4');
            _entities.Add("Upsilon", '\u03A5');
            _entities.Add("Phi", '\u03A6');
            _entities.Add("Chi", '\u03A7');
            _entities.Add("Psi", '\u03A8');
            _entities.Add("Omega", '\u03A9');
            _entities.Add("alpha", '\u03B1');
            _entities.Add("beta", '\u03B2');
            _entities.Add("gamma", '\u03B3');
            _entities.Add("delta", '\u03B4');
            _entities.Add("epsilon", '\u03B5');
            _entities.Add("zeta", '\u03B6');
            _entities.Add("eta", '\u03B7');
            _entities.Add("theta", '\u03B8');
            _entities.Add("iota", '\u03B9');
            _entities.Add("kappa", '\u03BA');
            _entities.Add("lambda", '\u03BB');
            _entities.Add("mu", '\u03BC');
            _entities.Add("nu", '\u03BD');
            _entities.Add("xi", '\u03BE');
            _entities.Add("omicron", '\u03BF');
            _entities.Add("pi", '\u03C0');
            _entities.Add("rho", '\u03C1');
            _entities.Add("sigmaf", '\u03C2');
            _entities.Add("sigma", '\u03C3');
            _entities.Add("tau", '\u03C4');
            _entities.Add("upsilon", '\u03C5');
            _entities.Add("phi", '\u03C6');
            _entities.Add("chi", '\u03C7');
            _entities.Add("psi", '\u03C8');
            _entities.Add("omega", '\u03C9');
            _entities.Add("thetasym", '\u03D1');
            _entities.Add("upsih", '\u03D2');
            _entities.Add("piv", '\u03D6');
            _entities.Add("bull", '\u2022');
            _entities.Add("hellip", '\u2026');
            _entities.Add("prime", '\u2032');
            _entities.Add("Prime", '\u2033');
            _entities.Add("oline", '\u203E');
            _entities.Add("frasl", '\u2044');
            _entities.Add("weierp", '\u2118');
            _entities.Add("image", '\u2111');
            _entities.Add("real", '\u211C');
            _entities.Add("trade", '\u2122');
            _entities.Add("alefsym", '\u2135');
            _entities.Add("larr", '\u2190');
            _entities.Add("uarr", '\u2191');
            _entities.Add("rarr", '\u2192');
            _entities.Add("darr", '\u2193');
            _entities.Add("harr", '\u2194');
            _entities.Add("crarr", '\u21B5');
            _entities.Add("lArr", '\u21D0');
            _entities.Add("uArr", '\u21D1');
            _entities.Add("rArr", '\u21D2');
            _entities.Add("dArr", '\u21D3');
            _entities.Add("hArr", '\u21D4');
            _entities.Add("forall", '\u2200');
            _entities.Add("part", '\u2202');
            _entities.Add("exist", '\u2203');
            _entities.Add("empty", '\u2205');
            _entities.Add("nabla", '\u2207');
            _entities.Add("isin", '\u2208');
            _entities.Add("notin", '\u2209');
            _entities.Add("ni", '\u220B');
            _entities.Add("prod", '\u220F');
            _entities.Add("sum", '\u2211');
            _entities.Add("minus", '\u2212');
            _entities.Add("lowast", '\u2217');
            _entities.Add("radic", '\u221A');
            _entities.Add("prop", '\u221D');
            _entities.Add("infin", '\u221E');
            _entities.Add("ang", '\u2220');
            _entities.Add("and", '\u2227');
            _entities.Add("or", '\u2228');
            _entities.Add("cap", '\u2229');
            _entities.Add("cup", '\u222A');
            _entities.Add("int", '\u222B');
            _entities.Add("there4", '\u2234');
            _entities.Add("sim", '\u223C');
            _entities.Add("cong", '\u2245');
            _entities.Add("asymp", '\u2248');
            _entities.Add("ne", '\u2260');
            _entities.Add("equiv", '\u2261');
            _entities.Add("le", '\u2264');
            _entities.Add("ge", '\u2265');
            _entities.Add("sub", '\u2282');
            _entities.Add("sup", '\u2283');
            _entities.Add("nsub", '\u2284');
            _entities.Add("sube", '\u2286');
            _entities.Add("supe", '\u2287');
            _entities.Add("oplus", '\u2295');
            _entities.Add("otimes", '\u2297');
            _entities.Add("perp", '\u22A5');
            _entities.Add("sdot", '\u22C5');
            _entities.Add("lceil", '\u2308');
            _entities.Add("rceil", '\u2309');
            _entities.Add("lfloor", '\u230A');
            _entities.Add("rfloor", '\u230B');
            _entities.Add("lang", '\u2329');
            _entities.Add("rang", '\u232A');
            _entities.Add("loz", '\u25CA');
            _entities.Add("spades", '\u2660');
            _entities.Add("clubs", '\u2663');
            _entities.Add("hearts", '\u2665');
            _entities.Add("diams", '\u2666');
            _entities.Add("quot", '\u0022');
            _entities.Add("amp", '\u0026');
            _entities.Add("lt", '\u003C');
            _entities.Add("gt", '\u003E');
            _entities.Add("OElig", '\u0152');
            _entities.Add("oelig", '\u0153');
            _entities.Add("Scaron", '\u0160');
            _entities.Add("scaron", '\u0161');
            _entities.Add("Yuml", '\u0178');
            _entities.Add("circ", '\u02C6');
            _entities.Add("tilde", '\u02DC');
            _entities.Add("ensp", '\u2002');
            _entities.Add("emsp", '\u2003');
            _entities.Add("thinsp", '\u2009');
            _entities.Add("zwnj", '\u200C');
            _entities.Add("zwj", '\u200D');
            _entities.Add("lrm", '\u200E');
            _entities.Add("rlm", '\u200F');
            _entities.Add("ndash", '\u2013');
            _entities.Add("mdash", '\u2014');
            _entities.Add("lsquo", '\u2018');
            _entities.Add("rsquo", '\u2019');
            _entities.Add("sbquo", '\u201A');
            _entities.Add("ldquo", '\u201C');
            _entities.Add("rdquo", '\u201D');
            _entities.Add("bdquo", '\u201E');
            _entities.Add("dagger", '\u2020');
            _entities.Add("Dagger", '\u2021');
            _entities.Add("permil", '\u2030');
            _entities.Add("lsaquo", '\u2039');
            _entities.Add("rsaquo", '\u203A');
            _entities.Add("euro", '\u20AC');
        }

        private static bool isAlphabet(char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        }

        private static bool isNumeric(char c)
        {
            return c >= '0' && c <= '9';
        }

        private static bool isUnreserved(char c)
        {
            return c == '*'
                   || c == '-'
                   || c == '.'
                   || c == '_';
        }

        private static bool isUnreservedInRfc2396(char c)
        {
            return c == '!'
                   || c == '\''
                   || c == '('
                   || c == ')'
                   || c == '*'
                   || c == '-'
                   || c == '.'
                   || c == '_'
                   || c == '~';
        }

        private static bool isUnreservedInRfc3986(char c)
        {
            return c == '-'
                   || c == '.'
                   || c == '_'
                   || c == '~';
        }

        private static byte[] urlDecodeToBytes(byte[] bytes, int offset, int count)
        {
            using (var buff = new MemoryStream())
            {
                var end = offset + count - 1;

                for (var i = offset; i <= end; i++)
                {
                    var b = bytes[i];
                    var c = (char)b;

                    if (c == '%')
                    {
                        if (i > end - 2)
                            break;

                        var num = getNumber(bytes, i + 1, 2);

                        if (num == -1)
                            break;

                        buff.WriteByte((byte)num);

                        i += 2;

                        continue;
                    }

                    if (c == '+')
                    {
                        buff.WriteByte((byte)' ');

                        continue;
                    }

                    buff.WriteByte(b);
                }

                buff.Close();

                return buff.ToArray();
            }
        }

        private static void urlEncode(byte b, Stream output)
        {
            if (b > 31 && b < 127)
            {
                var c = (char)b;

                if (c == ' ')
                {
                    output.WriteByte((byte)'+');

                    return;
                }

                if (isNumeric(c))
                {
                    output.WriteByte(b);

                    return;
                }

                if (isAlphabet(c))
                {
                    output.WriteByte(b);

                    return;
                }

                if (isUnreserved(c))
                {
                    output.WriteByte(b);

                    return;
                }
            }

            var i = (int)b;
            var bytes = new byte[] {
                    (byte) '%',
                    (byte) _hexChars[i >> 4],
                    (byte) _hexChars[i & 0x0F]
                  };

            output.Write(bytes, 0, 3);
        }

        private static byte[] urlEncodeToBytes(byte[] bytes, int offset, int count)
        {
            using (var buff = new MemoryStream())
            {
                var end = offset + count - 1;

                for (var i = offset; i <= end; i++)
                    urlEncode(bytes[i], buff);

                buff.Close();

                return buff.ToArray();
            }
        }

        internal static Uri CreateRequestUrl(
          string requestUri,
          string host,
          bool websocketRequest,
          bool secure
        )
        {
            if (requestUri == null || requestUri.Length == 0)
                return null;

            if (host == null || host.Length == 0)
                return null;

            string schm = null;
            string path = null;

            if (requestUri.IndexOf('/') == 0)
            {
                path = requestUri;
            }
            else if (requestUri.MaybeUri())
            {
                Uri uri;

                if (!Uri.TryCreate(requestUri, UriKind.Absolute, out uri))
                    return null;

                schm = uri.Scheme;
                var valid = websocketRequest
                            ? schm == "ws" || schm == "wss"
                            : schm == "http" || schm == "https";

                if (!valid)
                    return null;

                host = uri.Authority;
                path = uri.PathAndQuery;
            }
            else if (requestUri == "*")
            {
            }
            else
            {
                // As the authority form.

                host = requestUri;
            }

            if (schm == null)
            {
                schm = websocketRequest
                       ? (secure ? "wss" : "ws")
                       : (secure ? "https" : "http");
            }

            if (host.IndexOf(':') == -1)
                host = String.Format("{0}:{1}", host, secure ? 443 : 80);

            var url = String.Format("{0}://{1}{2}", schm, host, path);
            Uri ret;

            return Uri.TryCreate(url, UriKind.Absolute, out ret) ? ret : null;
        }

        internal static IPrincipal CreateUser(
          string response,
          AuthenticationSchemes scheme,
          string realm,
          string method,
          Func<IIdentity, NetworkCredential> credentialsFinder
        )
        {
            if (response == null || response.Length == 0)
                return null;

            if (scheme == AuthenticationSchemes.Digest)
            {
                if (realm == null || realm.Length == 0)
                    return null;

                if (method == null || method.Length == 0)
                    return null;
            }
            else
            {
                if (scheme != AuthenticationSchemes.Basic)
                    return null;
            }

            if (credentialsFinder == null)
                return null;

            var compType = StringComparison.OrdinalIgnoreCase;

            if (!response.StartsWith(scheme.ToString(), compType))
                return null;

            var res = AuthenticationResponse.Parse(response);

            if (res == null)
                return null;

            var id = res.ToIdentity();

            if (id == null)
                return null;

            NetworkCredential cred = null;

            try
            {
                cred = credentialsFinder(id);
            }
            catch
            {
            }

            if (cred == null)
                return null;

            if (scheme == AuthenticationSchemes.Basic)
            {
                var basicId = (HttpBasicIdentity)id;

                return basicId.Password == cred.Password
                       ? new GenericPrincipal(id, cred.Roles)
                       : null;
            }

            var digestId = (HttpDigestIdentity)id;

            return digestId.IsValid(cred.Password, realm, method, null)
                   ? new GenericPrincipal(id, cred.Roles)
                   : null;
        }

        internal static Encoding GetEncoding(string contentType)
        {
            var name = "charset=";
            var compType = StringComparison.OrdinalIgnoreCase;

            foreach (var elm in contentType.SplitHeaderValue(';'))
            {
                var part = elm.Trim();

                if (!part.StartsWith(name, compType))
                    continue;

                var val = part.GetValue('=', true);

                if (val == null || val.Length == 0)
                    return null;

                return Encoding.GetEncoding(val);
            }

            return null;
        }

        internal static bool TryGetEncoding(
          string contentType,
          out Encoding result
        )
        {
            result = null;

            try
            {
                result = GetEncoding(contentType);
            }
            catch
            {
                return false;
            }

            return result != null;
        }

        public static string HtmlAttributeEncode(string s)
        {
            if (s == null)
                throw new ArgumentNullException("s");

            return s.Length > 0 ? htmlEncode(s, true) : s;
        }

        public static void HtmlAttributeEncode(string s, TextWriter output)
        {
            if (s == null)
                throw new ArgumentNullException("s");

            if (output == null)
                throw new ArgumentNullException("output");

            if (s.Length == 0)
                return;

            var encodedS = htmlEncode(s, true);

            output.Write(encodedS);
        }

        public static string HtmlDecode(string s)
        {
            if (s == null)
                throw new ArgumentNullException("s");

            return s.Length > 0 ? htmlDecode(s) : s;
        }

        public static void HtmlDecode(string s, TextWriter output)
        {
            if (s == null)
                throw new ArgumentNullException("s");

            if (output == null)
                throw new ArgumentNullException("output");

            if (s.Length == 0)
                return;

            var decodedS = htmlDecode(s);

            output.Write(decodedS);
        }

        public static string HtmlEncode(string s)
        {
            if (s == null)
                throw new ArgumentNullException("s");

            return s.Length > 0 ? htmlEncode(s, false) : s;
        }

        public static void HtmlEncode(string s, TextWriter output)
        {
            if (s == null)
                throw new ArgumentNullException("s");

            if (output == null)
                throw new ArgumentNullException("output");

            if (s.Length == 0)
                return;

            var encodedS = htmlEncode(s, false);

            output.Write(encodedS);
        }

        public static string UrlDecode(string s)
        {
            return UrlDecode(s, Encoding.UTF8);
        }

        public static string UrlDecode(byte[] bytes, Encoding encoding)
        {
            if (bytes == null)
                throw new ArgumentNullException("bytes");

            var len = bytes.Length;

            if (len == 0)
                return String.Empty;

            var decodedBytes = urlDecodeToBytes(bytes, 0, len);

            return (encoding ?? Encoding.UTF8).GetString(decodedBytes);
        }

        public static string UrlDecode(string s, Encoding encoding)
        {
            if (s == null)
                throw new ArgumentNullException("s");

            if (s.Length == 0)
                return s;

            var bytes = Encoding.ASCII.GetBytes(s);
            var decodedBytes = urlDecodeToBytes(bytes, 0, bytes.Length);

            return (encoding ?? Encoding.UTF8).GetString(decodedBytes);
        }

        public static string UrlDecode(
          byte[] bytes,
          int offset,
          int count,
          Encoding encoding
        )
        {
            if (bytes == null)
                throw new ArgumentNullException("bytes");

            var len = bytes.Length;

            if (len == 0)
            {
                if (offset != 0)
                    throw new ArgumentOutOfRangeException("offset");

                if (count != 0)
                    throw new ArgumentOutOfRangeException("count");

                return String.Empty;
            }

            if (offset < 0 || offset >= len)
                throw new ArgumentOutOfRangeException("offset");

            if (count < 0 || count > len - offset)
                throw new ArgumentOutOfRangeException("count");

            if (count == 0)
                return String.Empty;

            var decodedBytes = urlDecodeToBytes(bytes, offset, count);

            return (encoding ?? Encoding.UTF8).GetString(decodedBytes);
        }

        public static byte[] UrlDecodeToBytes(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException("bytes");

            var len = bytes.Length;

            return len > 0 ? urlDecodeToBytes(bytes, 0, len) : bytes;
        }

        public static byte[] UrlDecodeToBytes(string s)
        {
            if (s == null)
                throw new ArgumentNullException("s");

            if (s.Length == 0)
                return new byte[0];

            var bytes = Encoding.ASCII.GetBytes(s);

            return urlDecodeToBytes(bytes, 0, bytes.Length);
        }

        public static byte[] UrlDecodeToBytes(byte[] bytes, int offset, int count)
        {
            if (bytes == null)
                throw new ArgumentNullException("bytes");

            var len = bytes.Length;

            if (len == 0)
            {
                if (offset != 0)
                    throw new ArgumentOutOfRangeException("offset");

                if (count != 0)
                    throw new ArgumentOutOfRangeException("count");

                return bytes;
            }

            if (offset < 0 || offset >= len)
                throw new ArgumentOutOfRangeException("offset");

            if (count < 0 || count > len - offset)
                throw new ArgumentOutOfRangeException("count");

            return count > 0 ? urlDecodeToBytes(bytes, offset, count) : new byte[0];
        }

        public static string UrlEncode(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException("bytes");

            var len = bytes.Length;

            if (len == 0)
                return String.Empty;

            var encodedBytes = urlEncodeToBytes(bytes, 0, len);

            return Encoding.ASCII.GetString(encodedBytes);
        }

        public static string UrlEncode(string s)
        {
            return UrlEncode(s, Encoding.UTF8);
        }

        public static string UrlEncode(string s, Encoding encoding)
        {
            if (s == null)
                throw new ArgumentNullException("s");

            var len = s.Length;

            if (len == 0)
                return s;

            if (encoding == null)
                encoding = Encoding.UTF8;

            var maxCnt = encoding.GetMaxByteCount(len);
            var bytes = new byte[maxCnt];
            var cnt = encoding.GetBytes(s, 0, len, bytes, 0);
            var encodedBytes = urlEncodeToBytes(bytes, 0, cnt);

            return Encoding.ASCII.GetString(encodedBytes);
        }

        public static string UrlEncode(byte[] bytes, int offset, int count)
        {
            if (bytes == null)
                throw new ArgumentNullException("bytes");

            var len = bytes.Length;

            if (len == 0)
            {
                if (offset != 0)
                    throw new ArgumentOutOfRangeException("offset");

                if (count != 0)
                    throw new ArgumentOutOfRangeException("count");

                return String.Empty;
            }

            if (offset < 0 || offset >= len)
                throw new ArgumentOutOfRangeException("offset");

            if (count < 0 || count > len - offset)
                throw new ArgumentOutOfRangeException("count");

            if (count == 0)
                return String.Empty;

            var encodedBytes = urlEncodeToBytes(bytes, offset, count);

            return Encoding.ASCII.GetString(encodedBytes);
        }

        public static byte[] UrlEncodeToBytes(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException("bytes");

            var len = bytes.Length;

            return len > 0 ? urlEncodeToBytes(bytes, 0, len) : bytes;
        }

        public static byte[] UrlEncodeToBytes(string s)
        {
            return UrlEncodeToBytes(s, Encoding.UTF8);
        }

        public static byte[] UrlEncodeToBytes(string s, Encoding encoding)
        {
            if (s == null)
                throw new ArgumentNullException("s");

            if (s.Length == 0)
                return new byte[0];

            var bytes = (encoding ?? Encoding.UTF8).GetBytes(s);

            return urlEncodeToBytes(bytes, 0, bytes.Length);
        }

        public static byte[] UrlEncodeToBytes(byte[] bytes, int offset, int count)
        {
            if (bytes == null)
                throw new ArgumentNullException("bytes");

            var len = bytes.Length;

            if (len == 0)
            {
                if (offset != 0)
                    throw new ArgumentOutOfRangeException("offset");

                if (count != 0)
                    throw new ArgumentOutOfRangeException("count");

                return bytes;
            }

            if (offset < 0 || offset >= len)
                throw new ArgumentOutOfRangeException("offset");

            if (count < 0 || count > len - offset)
                throw new ArgumentOutOfRangeException("count");

            return count > 0 ? urlEncodeToBytes(bytes, offset, count) : new byte[0];
        }
    }
    //=============================================================================
    /// <summary>
    /// Provides the HTTP version numbers.
    /// </summary>
    public class HttpVersion
    {
        /// <summary>
        /// Provides a <see cref="Version"/> instance for the HTTP/1.0.
        /// </summary>
        public static readonly Version Version10 = new Version(1, 0);

        /// <summary>
        /// Provides a <see cref="Version"/> instance for the HTTP/1.1.
        /// </summary>
        public static readonly Version Version11 = new Version(1, 1);

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpVersion"/> class.
        /// </summary>
        public HttpVersion()
        {
        }
    }
    //========================================================================================
    internal enum InputChunkState
    {
        None,
        Data,
        DataEnded,
        Trailer,
        End
    }
    //========================================================================================
    internal enum InputState
    {
        RequestLine,
        Headers
    }
    //========================================================================================
    internal enum LineState
    {
        None,
        Cr,
        Lf
    }
    //========================================================================================
    /// <summary>
    /// Provides the credentials for the password-based authentication.
    /// </summary>
    public class NetworkCredential
    {
        private string _domain;
        private static readonly string[] _noRoles;
        private string _password;
        private string[] _roles;
        private string _username;

        static NetworkCredential()
        {
            _noRoles = new string[0];
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NetworkCredential"/> class
        /// with the specified username and password.
        /// </summary>
        /// <param name="username">
        /// A <see cref="string"/> that specifies the username associated with
        /// the credentials.
        /// </param>
        /// <param name="password">
        /// A <see cref="string"/> that specifies the password for the username
        /// associated with the credentials.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="username"/> is an empty string.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="username"/> is <see langword="null"/>.
        /// </exception>
        public NetworkCredential(string username, string password)
          : this(username, password, null, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NetworkCredential"/> class
        /// with the specified username, password, domain and roles.
        /// </summary>
        /// <param name="username">
        /// A <see cref="string"/> that specifies the username associated with
        /// the credentials.
        /// </param>
        /// <param name="password">
        /// A <see cref="string"/> that specifies the password for the username
        /// associated with the credentials.
        /// </param>
        /// <param name="domain">
        /// A <see cref="string"/> that specifies the domain associated with
        /// the credentials.
        /// </param>
        /// <param name="roles">
        /// An array of <see cref="string"/> that specifies the roles associated
        /// with the credentials if any.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="username"/> is an empty string.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="username"/> is <see langword="null"/>.
        /// </exception>
        public NetworkCredential(
          string username,
          string password,
          string domain,
          params string[] roles
        )
        {
            if (username == null)
                throw new ArgumentNullException("username");

            if (username.Length == 0)
                throw new ArgumentException("An empty string.", "username");

            _username = username;
            _password = password;
            _domain = domain;
            _roles = roles;
        }

        /// <summary>
        /// Gets the domain associated with the credentials.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the domain name
        ///   to which the username belongs.
        ///   </para>
        ///   <para>
        ///   An empty string if the value was initialized with
        ///   <see langword="null"/>.
        ///   </para>
        /// </value>
        public string Domain
        {
            get
            {
                return _domain ?? String.Empty;
            }

            internal set
            {
                _domain = value;
            }
        }

        /// <summary>
        /// Gets the password for the username associated with the credentials.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the password.
        ///   </para>
        ///   <para>
        ///   An empty string if the value was initialized with
        ///   <see langword="null"/>.
        ///   </para>
        /// </value>
        public string Password
        {
            get
            {
                return _password ?? String.Empty;
            }

            internal set
            {
                _password = value;
            }
        }

        /// <summary>
        /// Gets the roles associated with the credentials.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An array of <see cref="string"/> that represents the role names
        ///   to which the username belongs.
        ///   </para>
        ///   <para>
        ///   An empty array if the value was initialized with
        ///   <see langword="null"/>.
        ///   </para>
        /// </value>
        public string[] Roles
        {
            get
            {
                return _roles ?? _noRoles;
            }

            internal set
            {
                _roles = value;
            }
        }

        /// <summary>
        /// Gets the username associated with the credentials.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the username.
        /// </value>
        public string Username
        {
            get
            {
                return _username;
            }

            internal set
            {
                _username = value;
            }
        }
    }
    //====================================================================================
    internal sealed class QueryStringCollection : NameValueCollection
    {
        public QueryStringCollection()
        {
        }

        public QueryStringCollection(int capacity)
          : base(capacity)
        {
        }

        public static QueryStringCollection Parse(string query)
        {
            return Parse(query, Encoding.UTF8);
        }

        public static QueryStringCollection Parse(string query, Encoding encoding)
        {
            if (query == null)
                return new QueryStringCollection(1);

            if (query.Length == 0)
                return new QueryStringCollection(1);

            if (query == "?")
                return new QueryStringCollection(1);

            if (query[0] == '?')
                query = query.Substring(1);

            if (encoding == null)
                encoding = Encoding.UTF8;

            var ret = new QueryStringCollection();

            foreach (var component in query.Split('&'))
            {
                var len = component.Length;

                if (len == 0)
                    continue;

                if (component == "=")
                    continue;

                string name = null;
                string val = null;

                var idx = component.IndexOf('=');

                if (idx < 0)
                {
                    val = component.UrlDecode(encoding);
                }
                else if (idx == 0)
                {
                    val = component.Substring(1).UrlDecode(encoding);
                }
                else
                {
                    name = component.Substring(0, idx).UrlDecode(encoding);

                    var start = idx + 1;
                    val = start < len
                          ? component.Substring(start).UrlDecode(encoding)
                          : String.Empty;
                }

                ret.Add(name, val);
            }

            return ret;
        }

        public override string ToString()
        {
            if (Count == 0)
                return String.Empty;

            var buff = new StringBuilder();

            var fmt = "{0}={1}&";

            foreach (var key in AllKeys)
                buff.AppendFormat(fmt, key, this[key]);

            buff.Length--;

            return buff.ToString();
        }
    }
    //=======================================================================================
    internal class ReadBufferState
    {
        private HttpStreamAsyncResult _asyncResult;
        private byte[] _buffer;
        private int _count;
        private int _initialCount;
        private int _offset;

        public ReadBufferState(
          byte[] buffer,
          int offset,
          int count,
          HttpStreamAsyncResult asyncResult
        )
        {
            _buffer = buffer;
            _offset = offset;
            _count = count;
            _asyncResult = asyncResult;

            _initialCount = count;
        }

        public HttpStreamAsyncResult AsyncResult
        {
            get
            {
                return _asyncResult;
            }

            set
            {
                _asyncResult = value;
            }
        }

        public byte[] Buffer
        {
            get
            {
                return _buffer;
            }

            set
            {
                _buffer = value;
            }
        }

        public int Count
        {
            get
            {
                return _count;
            }

            set
            {
                _count = value;
            }
        }

        public int InitialCount
        {
            get
            {
                return _initialCount;
            }

            set
            {
                _initialCount = value;
            }
        }

        public int Offset
        {
            get
            {
                return _offset;
            }

            set
            {
                _offset = value;
            }
        }
    }
    //==================================================================================
    internal class RequestStream : Stream
    {
        private long _bodyLeft;
        private int _count;
        private bool _disposed;
        private byte[] _initialBuffer;
        private Stream _innerStream;
        private int _offset;

        internal RequestStream(
          Stream innerStream,
          byte[] initialBuffer,
          int offset,
          int count,
          long contentLength
        )
        {
            _innerStream = innerStream;
            _initialBuffer = initialBuffer;
            _offset = offset;
            _count = count;
            _bodyLeft = contentLength;
        }

        internal int Count
        {
            get
            {
                return _count;
            }
        }

        internal byte[] InitialBuffer
        {
            get
            {
                return _initialBuffer;
            }
        }

        internal string ObjectName
        {
            get
            {
                return GetType().ToString();
            }
        }

        internal int Offset
        {
            get
            {
                return _offset;
            }
        }

        public override bool CanRead
        {
            get
            {
                return true;
            }
        }

        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }

        public override bool CanWrite
        {
            get
            {
                return false;
            }
        }

        public override long Length
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override long Position
        {
            get
            {
                throw new NotSupportedException();
            }

            set
            {
                throw new NotSupportedException();
            }
        }

        private int fillFromInitialBuffer(byte[] buffer, int offset, int count)
        {
            // This method returns a int:
            // - > 0 The number of bytes read from the initial buffer
            // - 0   No more bytes read from the initial buffer
            // - -1  No more content data

            if (_bodyLeft == 0)
                return -1;

            if (_count == 0)
                return 0;

            if (count > _count)
                count = _count;

            if (_bodyLeft > 0 && _bodyLeft < count)
                count = (int)_bodyLeft;

            Buffer.BlockCopy(_initialBuffer, _offset, buffer, offset, count);

            _offset += count;
            _count -= count;

            if (_bodyLeft > 0)
                _bodyLeft -= count;

            return count;
        }

        public override IAsyncResult BeginRead(
          byte[] buffer,
          int offset,
          int count,
          AsyncCallback callback,
          object state
        )
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            if (buffer == null)
                throw new ArgumentNullException("buffer");

            if (offset < 0)
            {
                var msg = "A negative value.";

                throw new ArgumentOutOfRangeException("offset", msg);
            }

            if (count < 0)
            {
                var msg = "A negative value.";

                throw new ArgumentOutOfRangeException("count", msg);
            }

            var len = buffer.Length;

            if (offset + count > len)
            {
                var msg = "The sum of offset and count is greater than the length of buffer.";

                throw new ArgumentException(msg);
            }

            if (count == 0)
                return _innerStream.BeginRead(buffer, offset, 0, callback, state);

            var nread = fillFromInitialBuffer(buffer, offset, count);

            if (nread != 0)
            {
                var ares = new HttpStreamAsyncResult(callback, state);

                ares.Buffer = buffer;
                ares.Offset = offset;
                ares.Count = count;
                ares.SyncRead = nread > 0 ? nread : 0;

                ares.Complete();

                return ares;
            }

            if (_bodyLeft > 0 && _bodyLeft < count)
                count = (int)_bodyLeft;

            return _innerStream.BeginRead(buffer, offset, count, callback, state);
        }

        public override IAsyncResult BeginWrite(
          byte[] buffer,
          int offset,
          int count,
          AsyncCallback callback,
          object state
        )
        {
            throw new NotSupportedException();
        }

        public override void Close()
        {
            _disposed = true;
        }

        public override int EndRead(IAsyncResult asyncResult)
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            if (asyncResult == null)
                throw new ArgumentNullException("asyncResult");

            if (asyncResult is HttpStreamAsyncResult)
            {
                var ares = (HttpStreamAsyncResult)asyncResult;

                if (!ares.IsCompleted)
                    ares.AsyncWaitHandle.WaitOne();

                return ares.SyncRead;
            }

            var nread = _innerStream.EndRead(asyncResult);

            if (nread > 0 && _bodyLeft > 0)
                _bodyLeft -= nread;

            return nread;
        }

        public override void EndWrite(IAsyncResult asyncResult)
        {
            throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            if (buffer == null)
                throw new ArgumentNullException("buffer");

            if (offset < 0)
            {
                var msg = "A negative value.";

                throw new ArgumentOutOfRangeException("offset", msg);
            }

            if (count < 0)
            {
                var msg = "A negative value.";

                throw new ArgumentOutOfRangeException("count", msg);
            }

            var len = buffer.Length;

            if (offset + count > len)
            {
                var msg = "The sum of offset and count is greater than the length of buffer.";

                throw new ArgumentException(msg);
            }

            if (count == 0)
                return 0;

            var nread = fillFromInitialBuffer(buffer, offset, count);

            if (nread == -1)
                return 0;

            if (nread > 0)
                return nread;

            if (_bodyLeft > 0 && _bodyLeft < count)
                count = (int)_bodyLeft;

            nread = _innerStream.Read(buffer, offset, count);

            if (nread > 0 && _bodyLeft > 0)
                _bodyLeft -= nread;

            return nread;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }
    //==================================================================================
    internal class ResponseStream : Stream
    {
        private MemoryStream _bodyBuffer;
        private static readonly byte[] _crlf;
        private bool _disposed;
        private Stream _innerStream;
        private static readonly byte[] _lastChunk;
        private static readonly int _maxHeadersLength;
        private HttpListenerResponse _response;
        private bool _sendChunked;
        private Action<byte[], int, int> _write;
        private Action<byte[], int, int> _writeBody;
        private Action<byte[], int, int> _writeChunked;

        static ResponseStream()
        {
            _crlf = new byte[] { 13, 10 }; // "\r\n"
            _lastChunk = new byte[] { 48, 13, 10, 13, 10 }; // "0\r\n\r\n"
            _maxHeadersLength = 32768;
        }

        internal ResponseStream(
          Stream innerStream,
          HttpListenerResponse response,
          bool ignoreWriteExceptions
        )
        {
            _innerStream = innerStream;
            _response = response;

            if (ignoreWriteExceptions)
            {
                _write = writeWithoutThrowingException;
                _writeChunked = writeChunkedWithoutThrowingException;
            }
            else
            {
                _write = innerStream.Write;
                _writeChunked = writeChunked;
            }

            _bodyBuffer = new MemoryStream();
        }

        internal string ObjectName
        {
            get
            {
                return GetType().ToString();
            }
        }

        public override bool CanRead
        {
            get
            {
                return false;
            }
        }

        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }

        public override bool CanWrite
        {
            get
            {
                return !_disposed;
            }
        }

        public override long Length
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        public override long Position
        {
            get
            {
                throw new NotSupportedException();
            }

            set
            {
                throw new NotSupportedException();
            }
        }

        private bool flush(bool closing)
        {
            if (!_response.HeadersSent)
            {
                if (!flushHeaders())
                    return false;

                _response.HeadersSent = true;

                _sendChunked = _response.SendChunked;
                _writeBody = _sendChunked ? _writeChunked : _write;
            }

            flushBody(closing);

            return true;
        }

        private void flushBody(bool closing)
        {
            using (_bodyBuffer)
            {
                var len = _bodyBuffer.Length;

                if (len > Int32.MaxValue)
                {
                    _bodyBuffer.Position = 0;

                    var buffLen = 1024;
                    var buff = new byte[buffLen];
                    var nread = 0;

                    while (true)
                    {
                        nread = _bodyBuffer.Read(buff, 0, buffLen);

                        if (nread <= 0)
                            break;

                        _writeBody(buff, 0, nread);
                    }
                }
                else if (len > 0)
                {
                    var buff = _bodyBuffer.GetBuffer();

                    _writeBody(buff, 0, (int)len);
                }
            }

            if (!closing)
            {
                _bodyBuffer = new MemoryStream();

                return;
            }

            if (_sendChunked)
                _write(_lastChunk, 0, 5);

            _bodyBuffer = null;
        }

        private bool flushHeaders()
        {
            if (!_response.SendChunked)
            {
                if (_response.ContentLength64 != _bodyBuffer.Length)
                    return false;
            }

            var headers = _response.FullHeaders;

            var stream = new MemoryStream();
            var enc = Encoding.UTF8;

            using (var writer = new StreamWriter(stream, enc, 256))
            {
                writer.Write(_response.StatusLine);

                var s = headers.ToStringMultiValue(true);

                writer.Write(s);
                writer.Flush();

                var start = enc.GetPreamble().Length;
                var len = stream.Length - start;

                if (len > _maxHeadersLength)
                    return false;

                var buff = stream.GetBuffer();

                _write(buff, start, (int)len);
            }

            _response.CloseConnection = headers["Connection"] == "close";

            return true;
        }

        private static byte[] getChunkSizeStringAsBytes(int size)
        {
            var fmt = "{0:x}\r\n";
            var s = String.Format(fmt, size);

            return Encoding.ASCII.GetBytes(s);
        }

        private void writeChunked(byte[] buffer, int offset, int count)
        {
            var size = getChunkSizeStringAsBytes(count);

            _innerStream.Write(size, 0, size.Length);
            _innerStream.Write(buffer, offset, count);
            _innerStream.Write(_crlf, 0, 2);
        }

        private void writeChunkedWithoutThrowingException(
          byte[] buffer,
          int offset,
          int count
        )
        {
            try
            {
                writeChunked(buffer, offset, count);
            }
            catch
            {
            }
        }

        private void writeWithoutThrowingException(
          byte[] buffer,
          int offset,
          int count
        )
        {
            try
            {
                _innerStream.Write(buffer, offset, count);
            }
            catch
            {
            }
        }

        internal void Close(bool force)
        {
            if (_disposed)
                return;

            _disposed = true;

            if (!force)
            {
                if (flush(true))
                {
                    _response.Close();

                    _response = null;
                    _innerStream = null;

                    return;
                }

                _response.CloseConnection = true;
            }

            if (_sendChunked)
                _write(_lastChunk, 0, 5);

            _bodyBuffer.Dispose();
            _response.Abort();

            _bodyBuffer = null;
            _response = null;
            _innerStream = null;
        }

        internal void InternalWrite(byte[] buffer, int offset, int count)
        {
            _write(buffer, offset, count);
        }

        public override IAsyncResult BeginRead(
          byte[] buffer,
          int offset,
          int count,
          AsyncCallback callback,
          object state
        )
        {
            throw new NotSupportedException();
        }

        public override IAsyncResult BeginWrite(
          byte[] buffer,
          int offset,
          int count,
          AsyncCallback callback,
          object state
        )
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            return _bodyBuffer.BeginWrite(buffer, offset, count, callback, state);
        }

        public override void Close()
        {
            Close(false);
        }

        protected override void Dispose(bool disposing)
        {
            Close(!disposing);
        }

        public override int EndRead(IAsyncResult asyncResult)
        {
            throw new NotSupportedException();
        }

        public override void EndWrite(IAsyncResult asyncResult)
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            _bodyBuffer.EndWrite(asyncResult);
        }

        public override void Flush()
        {
            if (_disposed)
                return;

            var sendChunked = _sendChunked || _response.SendChunked;

            if (!sendChunked)
                return;

            flush(false);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_disposed)
                throw new ObjectDisposedException(ObjectName);

            _bodyBuffer.Write(buffer, offset, count);
        }
    }
    //==================================================================================
    /// <summary>
    /// Stores the parameters for <see cref="SslStream"/> instances used by
    /// a server.
    /// </summary>
    public class ServerSslConfiguration
    {
        private bool _checkCertRevocation;
        private bool _clientCertRequired;
        private RemoteCertificateValidationCallback _clientCertValidationCallback;
        private SslProtocols _enabledSslProtocols;
        private X509Certificate2 _serverCert;

        /// <summary>
        /// Initializes a new instance of the <see cref="ServerSslConfiguration"/>
        /// class.
        /// </summary>
        public ServerSslConfiguration()
        {
            _enabledSslProtocols = SslProtocols.None;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ServerSslConfiguration"/>
        /// class copying from the specified configuration.
        /// </summary>
        /// <param name="configuration">
        /// A <see cref="ServerSslConfiguration"/> from which to copy.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="configuration"/> is <see langword="null"/>.
        /// </exception>
        public ServerSslConfiguration(ServerSslConfiguration configuration)
        {
            if (configuration == null)
                throw new ArgumentNullException("configuration");

            _checkCertRevocation = configuration._checkCertRevocation;
            _clientCertRequired = configuration._clientCertRequired;
            _clientCertValidationCallback = configuration._clientCertValidationCallback;
            _enabledSslProtocols = configuration._enabledSslProtocols;
            _serverCert = configuration._serverCert;
        }

        /// <summary>
        /// Gets or sets a value indicating whether the certificate revocation
        /// list is checked during authentication.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the certificate revocation list is checked during
        ///   authentication; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool CheckCertificateRevocation
        {
            get
            {
                return _checkCertRevocation;
            }

            set
            {
                _checkCertRevocation = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether each client is asked for
        /// a certificate for authentication.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if each client is asked for a certificate for
        ///   authentication; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool ClientCertificateRequired
        {
            get
            {
                return _clientCertRequired;
            }

            set
            {
                _clientCertRequired = value;
            }
        }

        /// <summary>
        /// Gets or sets the callback used to validate the certificate supplied by
        /// each client.
        /// </summary>
        /// <remarks>
        /// The certificate is valid if the callback returns <c>true</c>.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="RemoteCertificateValidationCallback"/> delegate.
        ///   </para>
        ///   <para>
        ///   It represents the delegate called when the server validates
        ///   the certificate.
        ///   </para>
        ///   <para>
        ///   The default value invokes a method that only returns <c>true</c>.
        ///   </para>
        /// </value>
        public RemoteCertificateValidationCallback ClientCertificateValidationCallback
        {
            get
            {
                if (_clientCertValidationCallback == null)
                    _clientCertValidationCallback = defaultValidateClientCertificate;

                return _clientCertValidationCallback;
            }

            set
            {
                _clientCertValidationCallback = value;
            }
        }

        /// <summary>
        /// Gets or sets the enabled versions of the SSL/TLS protocols.
        /// </summary>
        /// <value>
        ///   <para>
        ///   Any of the <see cref="SslProtocols"/> enum values.
        ///   </para>
        ///   <para>
        ///   It represents the enabled versions of the SSL/TLS protocols.
        ///   </para>
        ///   <para>
        ///   The default value is <see cref="SslProtocols.None"/>.
        ///   </para>
        /// </value>
        public SslProtocols EnabledSslProtocols
        {
            get
            {
                return _enabledSslProtocols;
            }

            set
            {
                _enabledSslProtocols = value;
            }
        }

        /// <summary>
        /// Gets or sets the certificate used to authenticate the server.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="X509Certificate2"/> that represents an X.509 certificate.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not present.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        public X509Certificate2 ServerCertificate
        {
            get
            {
                return _serverCert;
            }

            set
            {
                _serverCert = value;
            }
        }

        private static bool defaultValidateClientCertificate(
          object sender,
          X509Certificate certificate,
          X509Chain chain,
          SslPolicyErrors sslPolicyErrors
        )
        {
            return true;
        }
    }
    //==================================================================================
    /// <summary>
    /// Provides a collection of the HTTP headers associated with a request or
    /// response.
    /// </summary>
    [Serializable]
    [ComVisible(true)]
    public class WebHeaderCollection : NameValueCollection, ISerializable
    {
        private static readonly Dictionary<string, HttpHeaderInfo> _headers;
        private bool _internallyUsed;
        private HttpHeaderType _state;

        static WebHeaderCollection()
        {
            _headers =
              new Dictionary<string, HttpHeaderInfo>(
                StringComparer.InvariantCultureIgnoreCase
              )
              {
          {
            "Accept",
            new HttpHeaderInfo (
              "Accept",
              HttpHeaderType.Request
              | HttpHeaderType.Restricted
              | HttpHeaderType.MultiValue
            )
          },
          {
            "AcceptCharset",
            new HttpHeaderInfo (
              "Accept-Charset",
              HttpHeaderType.Request | HttpHeaderType.MultiValue
            )
          },
          {
            "AcceptEncoding",
            new HttpHeaderInfo (
              "Accept-Encoding",
              HttpHeaderType.Request | HttpHeaderType.MultiValue
            )
          },
          {
            "AcceptLanguage",
            new HttpHeaderInfo (
              "Accept-Language",
              HttpHeaderType.Request | HttpHeaderType.MultiValue
            )
          },
          {
            "AcceptRanges",
            new HttpHeaderInfo (
              "Accept-Ranges",
              HttpHeaderType.Response | HttpHeaderType.MultiValue
            )
          },
          {
            "Age",
            new HttpHeaderInfo (
              "Age",
              HttpHeaderType.Response
            )
          },
          {
            "Allow",
            new HttpHeaderInfo (
              "Allow",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.MultiValue
            )
          },
          {
            "Authorization",
            new HttpHeaderInfo (
              "Authorization",
              HttpHeaderType.Request | HttpHeaderType.MultiValue
            )
          },
          {
            "CacheControl",
            new HttpHeaderInfo (
              "Cache-Control",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.MultiValue
            )
          },
          {
            "Connection",
            new HttpHeaderInfo (
              "Connection",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.Restricted
              | HttpHeaderType.MultiValue
            )
          },
          {
            "ContentEncoding",
            new HttpHeaderInfo (
              "Content-Encoding",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.MultiValue
            )
          },
          {
            "ContentLanguage",
            new HttpHeaderInfo (
              "Content-Language",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.MultiValue
            )
          },
          {
            "ContentLength",
            new HttpHeaderInfo (
              "Content-Length",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.Restricted
            )
          },
          {
            "ContentLocation",
            new HttpHeaderInfo (
              "Content-Location",
              HttpHeaderType.Request | HttpHeaderType.Response
            )
          },
          {
            "ContentMd5",
            new HttpHeaderInfo (
              "Content-MD5",
              HttpHeaderType.Request | HttpHeaderType.Response
            )
          },
          {
            "ContentRange",
            new HttpHeaderInfo (
              "Content-Range",
              HttpHeaderType.Request | HttpHeaderType.Response
            )
          },
          {
            "ContentType",
            new HttpHeaderInfo (
              "Content-Type",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.Restricted
            )
          },
          {
            "Cookie",
            new HttpHeaderInfo (
              "Cookie",
              HttpHeaderType.Request
            )
          },
          {
            "Cookie2",
            new HttpHeaderInfo (
              "Cookie2",
              HttpHeaderType.Request
            )
          },
          {
            "Date",
            new HttpHeaderInfo (
              "Date",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.Restricted
            )
          },
          {
            "Expect",
            new HttpHeaderInfo (
              "Expect",
              HttpHeaderType.Request
              | HttpHeaderType.Restricted
              | HttpHeaderType.MultiValue
            )
          },
          {
            "Expires",
            new HttpHeaderInfo (
              "Expires",
              HttpHeaderType.Request | HttpHeaderType.Response
            )
          },
          {
            "ETag",
            new HttpHeaderInfo (
              "ETag",
              HttpHeaderType.Response
            )
          },
          {
            "From",
            new HttpHeaderInfo (
              "From",
              HttpHeaderType.Request
            )
          },
          {
            "Host",
            new HttpHeaderInfo (
              "Host",
              HttpHeaderType.Request | HttpHeaderType.Restricted
            )
          },
          {
            "IfMatch",
            new HttpHeaderInfo (
              "If-Match",
              HttpHeaderType.Request | HttpHeaderType.MultiValue
            )
          },
          {
            "IfModifiedSince",
            new HttpHeaderInfo (
              "If-Modified-Since",
              HttpHeaderType.Request | HttpHeaderType.Restricted
            )
          },
          {
            "IfNoneMatch",
            new HttpHeaderInfo (
              "If-None-Match",
              HttpHeaderType.Request | HttpHeaderType.MultiValue
            )
          },
          {
            "IfRange",
            new HttpHeaderInfo (
              "If-Range",
              HttpHeaderType.Request
            )
          },
          {
            "IfUnmodifiedSince",
            new HttpHeaderInfo (
              "If-Unmodified-Since",
              HttpHeaderType.Request
            )
          },
          {
            "KeepAlive",
            new HttpHeaderInfo (
              "Keep-Alive",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.MultiValue
            )
          },
          {
            "LastModified",
            new HttpHeaderInfo (
              "Last-Modified",
              HttpHeaderType.Request | HttpHeaderType.Response
            )
          },
          {
            "Location",
            new HttpHeaderInfo (
              "Location",
              HttpHeaderType.Response
            )
          },
          {
            "MaxForwards",
            new HttpHeaderInfo (
              "Max-Forwards",
              HttpHeaderType.Request
            )
          },
          {
            "Pragma",
            new HttpHeaderInfo (
              "Pragma",
              HttpHeaderType.Request | HttpHeaderType.Response
            )
          },
          {
            "ProxyAuthenticate",
            new HttpHeaderInfo (
              "Proxy-Authenticate",
              HttpHeaderType.Response | HttpHeaderType.MultiValue
            )
          },
          {
            "ProxyAuthorization",
            new HttpHeaderInfo (
              "Proxy-Authorization",
              HttpHeaderType.Request
            )
          },
          {
            "ProxyConnection",
            new HttpHeaderInfo (
              "Proxy-Connection",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.Restricted
            )
          },
          {
            "Public",
            new HttpHeaderInfo (
              "Public",
              HttpHeaderType.Response | HttpHeaderType.MultiValue
            )
          },
          {
            "Range",
            new HttpHeaderInfo (
              "Range",
              HttpHeaderType.Request
              | HttpHeaderType.Restricted
              | HttpHeaderType.MultiValue
            )
          },
          {
            "Referer",
            new HttpHeaderInfo (
              "Referer",
              HttpHeaderType.Request | HttpHeaderType.Restricted
            )
          },
          {
            "RetryAfter",
            new HttpHeaderInfo (
              "Retry-After",
              HttpHeaderType.Response
            )
          },
          {
            "SecWebSocketAccept",
            new HttpHeaderInfo (
              "Sec-WebSocket-Accept",
              HttpHeaderType.Response | HttpHeaderType.Restricted
            )
          },
          {
            "SecWebSocketExtensions",
            new HttpHeaderInfo (
              "Sec-WebSocket-Extensions",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.Restricted
              | HttpHeaderType.MultiValueInRequest
            )
          },
          {
            "SecWebSocketKey",
            new HttpHeaderInfo (
              "Sec-WebSocket-Key",
              HttpHeaderType.Request | HttpHeaderType.Restricted
            )
          },
          {
            "SecWebSocketProtocol",
            new HttpHeaderInfo (
              "Sec-WebSocket-Protocol",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.MultiValueInRequest
            )
          },
          {
            "SecWebSocketVersion",
            new HttpHeaderInfo (
              "Sec-WebSocket-Version",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.Restricted
              | HttpHeaderType.MultiValueInResponse
            )
          },
          {
            "Server",
            new HttpHeaderInfo (
              "Server",
              HttpHeaderType.Response
            )
          },
          {
            "SetCookie",
            new HttpHeaderInfo (
              "Set-Cookie",
              HttpHeaderType.Response | HttpHeaderType.MultiValue
            )
          },
          {
            "SetCookie2",
            new HttpHeaderInfo (
              "Set-Cookie2",
              HttpHeaderType.Response | HttpHeaderType.MultiValue
            )
          },
          {
            "Te",
            new HttpHeaderInfo (
              "TE",
              HttpHeaderType.Request
            )
          },
          {
            "Trailer",
            new HttpHeaderInfo (
              "Trailer",
              HttpHeaderType.Request | HttpHeaderType.Response
            )
          },
          {
            "TransferEncoding",
            new HttpHeaderInfo (
              "Transfer-Encoding",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.Restricted
              | HttpHeaderType.MultiValue
            )
          },
          {
            "Translate",
            new HttpHeaderInfo (
              "Translate",
              HttpHeaderType.Request
            )
          },
          {
            "Upgrade",
            new HttpHeaderInfo (
              "Upgrade",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.MultiValue
            )
          },
          {
            "UserAgent",
            new HttpHeaderInfo (
              "User-Agent",
              HttpHeaderType.Request | HttpHeaderType.Restricted
            )
          },
          {
            "Vary",
            new HttpHeaderInfo (
              "Vary",
              HttpHeaderType.Response | HttpHeaderType.MultiValue
            )
          },
          {
            "Via",
            new HttpHeaderInfo (
              "Via",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.MultiValue
            )
          },
          {
            "Warning",
            new HttpHeaderInfo (
              "Warning",
              HttpHeaderType.Request
              | HttpHeaderType.Response
              | HttpHeaderType.MultiValue
            )
          },
          {
            "WwwAuthenticate",
            new HttpHeaderInfo (
              "WWW-Authenticate",
              HttpHeaderType.Response
              | HttpHeaderType.Restricted
              | HttpHeaderType.MultiValue
            )
          }
              };
        }

        internal WebHeaderCollection(HttpHeaderType state, bool internallyUsed)
        {
            _state = state;
            _internallyUsed = internallyUsed;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WebHeaderCollection"/>
        /// class with the specified serialized data.
        /// </summary>
        /// <param name="serializationInfo">
        /// A <see cref="SerializationInfo"/> that contains the serialized
        /// object data.
        /// </param>
        /// <param name="streamingContext">
        /// A <see cref="StreamingContext"/> that specifies the source for
        /// the deserialization.
        /// </param>
        /// <exception cref="ArgumentException">
        /// An element with the specified name is not found in
        /// <paramref name="serializationInfo"/>.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="serializationInfo"/> is <see langword="null"/>.
        /// </exception>
        protected WebHeaderCollection(
          SerializationInfo serializationInfo,
          StreamingContext streamingContext
        )
        {
            if (serializationInfo == null)
                throw new ArgumentNullException("serializationInfo");

            try
            {
                _internallyUsed = serializationInfo.GetBoolean("InternallyUsed");
                _state = (HttpHeaderType)serializationInfo.GetInt32("State");

                var cnt = serializationInfo.GetInt32("Count");

                for (var i = 0; i < cnt; i++)
                {
                    base.Add(
                      serializationInfo.GetString(i.ToString()),
                      serializationInfo.GetString((cnt + i).ToString())
                    );
                }
            }
            catch (SerializationException ex)
            {
                throw new ArgumentException(ex.Message, "serializationInfo", ex);
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WebHeaderCollection"/>
        /// class.
        /// </summary>
        public WebHeaderCollection()
        {
        }

        internal HttpHeaderType State
        {
            get
            {
                return _state;
            }
        }

        /// <summary>
        /// Gets all header names in the collection.
        /// </summary>
        /// <value>
        /// An array of <see cref="string"/> that contains all header names in
        /// the collection.
        /// </value>
        public override string[] AllKeys
        {
            get
            {
                return base.AllKeys;
            }
        }

        /// <summary>
        /// Gets the number of headers in the collection.
        /// </summary>
        /// <value>
        /// An <see cref="int"/> that represents the number of headers in
        /// the collection.
        /// </value>
        public override int Count
        {
            get
            {
                return base.Count;
            }
        }

        /// <summary>
        /// Gets or sets the specified request header.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the value of the request header.
        /// </value>
        /// <param name="header">
        ///   <para>
        ///   One of the <see cref="HttpRequestHeader"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the request header to get or set.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="header"/> is a restricted header.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="value"/> contains an invalid character.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of <paramref name="value"/> is greater than 65,535
        /// characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the request header.
        /// </exception>
        public string this[HttpRequestHeader header]
        {
            get
            {
                var key = header.ToString();
                var name = getHeaderName(key);

                return Get(name);
            }

            set
            {
                Add(header, value);
            }
        }

        /// <summary>
        /// Gets or sets the specified response header.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the value of the response header.
        /// </value>
        /// <param name="header">
        ///   <para>
        ///   One of the <see cref="HttpResponseHeader"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the response header to get or set.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="header"/> is a restricted header.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="value"/> contains an invalid character.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of <paramref name="value"/> is greater than 65,535
        /// characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the response header.
        /// </exception>
        public string this[HttpResponseHeader header]
        {
            get
            {
                var key = header.ToString();
                var name = getHeaderName(key);

                return Get(name);
            }

            set
            {
                Add(header, value);
            }
        }

        /// <summary>
        /// Gets a collection of header names in the collection.
        /// </summary>
        /// <value>
        /// A <see cref="NameObjectCollectionBase.KeysCollection"/> that contains
        /// all header names in the collection.
        /// </value>
        public override NameObjectCollectionBase.KeysCollection Keys
        {
            get
            {
                return base.Keys;
            }
        }

        private void add(string name, string value, HttpHeaderType headerType)
        {
            base.Add(name, value);

            if (_state != HttpHeaderType.Unspecified)
                return;

            if (headerType == HttpHeaderType.Unspecified)
                return;

            _state = headerType;
        }

        private void checkAllowed(HttpHeaderType headerType)
        {
            if (_state == HttpHeaderType.Unspecified)
                return;

            if (headerType == HttpHeaderType.Unspecified)
                return;

            if (headerType != _state)
            {
                var msg = "This instance does not allow the header.";

                throw new InvalidOperationException(msg);
            }
        }

        private static string checkName(string name, string paramName)
        {
            if (name == null)
            {
                var msg = "The name is null.";

                throw new ArgumentNullException(paramName, msg);
            }

            if (name.Length == 0)
            {
                var msg = "The name is an empty string.";

                throw new ArgumentException(msg, paramName);
            }

            name = name.Trim();

            if (name.Length == 0)
            {
                var msg = "The name is a string of spaces.";

                throw new ArgumentException(msg, paramName);
            }

            if (!name.IsToken())
            {
                var msg = "The name contains an invalid character.";

                throw new ArgumentException(msg, paramName);
            }

            return name;
        }

        private void checkRestricted(string name, HttpHeaderType headerType)
        {
            if (_internallyUsed)
                return;

            var res = headerType == HttpHeaderType.Response;

            if (isRestricted(name, res))
            {
                var msg = "The header is a restricted header.";

                throw new ArgumentException(msg);
            }
        }

        private static string checkValue(string value, string paramName)
        {
            if (value == null)
                return String.Empty;

            value = value.Trim();

            var len = value.Length;

            if (len == 0)
                return value;

            if (len > 65535)
            {
                var msg = "The length of the value is greater than 65,535 characters.";

                throw new ArgumentOutOfRangeException(paramName, msg);
            }

            if (!value.IsText())
            {
                var msg = "The value contains an invalid character.";

                throw new ArgumentException(msg, paramName);
            }

            return value;
        }

        private static HttpHeaderInfo getHeaderInfo(string name)
        {
            var compType = StringComparison.InvariantCultureIgnoreCase;

            foreach (var headerInfo in _headers.Values)
            {
                if (headerInfo.HeaderName.Equals(name, compType))
                    return headerInfo;
            }

            return null;
        }

        private static string getHeaderName(string key)
        {
            HttpHeaderInfo headerInfo;

            return _headers.TryGetValue(key, out headerInfo)
                   ? headerInfo.HeaderName
                   : null;
        }

        private static HttpHeaderType getHeaderType(string name)
        {
            var headerInfo = getHeaderInfo(name);

            if (headerInfo == null)
                return HttpHeaderType.Unspecified;

            if (headerInfo.IsRequest)
            {
                return !headerInfo.IsResponse
                       ? HttpHeaderType.Request
                       : HttpHeaderType.Unspecified;
            }

            return headerInfo.IsResponse
                   ? HttpHeaderType.Response
                   : HttpHeaderType.Unspecified;
        }

        private static bool isMultiValue(string name, bool response)
        {
            var headerInfo = getHeaderInfo(name);

            return headerInfo != null && headerInfo.IsMultiValue(response);
        }

        private static bool isRestricted(string name, bool response)
        {
            var headerInfo = getHeaderInfo(name);

            return headerInfo != null && headerInfo.IsRestricted(response);
        }

        private void set(string name, string value, HttpHeaderType headerType)
        {
            base.Set(name, value);

            if (_state != HttpHeaderType.Unspecified)
                return;

            if (headerType == HttpHeaderType.Unspecified)
                return;

            _state = headerType;
        }

        internal void InternalRemove(string name)
        {
            base.Remove(name);
        }

        internal void InternalSet(string header, bool response)
        {
            var idx = header.IndexOf(':');

            if (idx == -1)
            {
                var msg = "It does not contain a colon character.";

                throw new ArgumentException(msg, "header");
            }

            var name = header.Substring(0, idx);
            var val = idx < header.Length - 1
                      ? header.Substring(idx + 1)
                      : String.Empty;

            name = checkName(name, "header");
            val = checkValue(val, "header");

            if (isMultiValue(name, response))
            {
                base.Add(name, val);

                return;
            }

            base.Set(name, val);
        }

        internal void InternalSet(string name, string value, bool response)
        {
            value = checkValue(value, "value");

            if (isMultiValue(name, response))
            {
                base.Add(name, value);

                return;
            }

            base.Set(name, value);
        }

        internal string ToStringMultiValue(bool response)
        {
            var cnt = Count;

            if (cnt == 0)
                return "\r\n";

            var buff = new StringBuilder();

            var fmt = "{0}: {1}\r\n";

            for (var i = 0; i < cnt; i++)
            {
                var name = GetKey(i);

                if (isMultiValue(name, response))
                {
                    foreach (var val in GetValues(i))
                        buff.AppendFormat(fmt, name, val);

                    continue;
                }

                buff.AppendFormat(fmt, name, Get(i));
            }

            buff.Append("\r\n");

            return buff.ToString();
        }

        /// <summary>
        /// Adds a header to the collection without checking if the header is on
        /// the restricted header list.
        /// </summary>
        /// <param name="headerName">
        /// A <see cref="string"/> that specifies the name of the header to add.
        /// </param>
        /// <param name="headerValue">
        /// A <see cref="string"/> that specifies the value of the header to add.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="headerName"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="headerName"/> is a string of spaces.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="headerName"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="headerValue"/> contains an invalid character.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="headerName"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of <paramref name="headerValue"/> is greater than 65,535
        /// characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the header.
        /// </exception>
        protected void AddWithoutValidate(string headerName, string headerValue)
        {
            headerName = checkName(headerName, "headerName");
            headerValue = checkValue(headerValue, "headerValue");

            var headerType = getHeaderType(headerName);

            checkAllowed(headerType);

            add(headerName, headerValue, headerType);
        }

        /// <summary>
        /// Adds the specified header to the collection.
        /// </summary>
        /// <param name="header">
        /// A <see cref="string"/> that specifies the header to add,
        /// with the name and value separated by a colon character (':').
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="header"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="header"/> does not contain a colon character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The name part of <paramref name="header"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The name part of <paramref name="header"/> is a string of spaces.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The name part of <paramref name="header"/> contains an invalid
        ///   character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The value part of <paramref name="header"/> contains an invalid
        ///   character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="header"/> is a restricted header.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="header"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of the value part of <paramref name="header"/> is greater
        /// than 65,535 characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the header.
        /// </exception>
        public void Add(string header)
        {
            if (header == null)
                throw new ArgumentNullException("header");

            var len = header.Length;

            if (len == 0)
            {
                var msg = "An empty string.";

                throw new ArgumentException(msg, "header");
            }

            var idx = header.IndexOf(':');

            if (idx == -1)
            {
                var msg = "It does not contain a colon character.";

                throw new ArgumentException(msg, "header");
            }

            var name = header.Substring(0, idx);
            var val = idx < len - 1 ? header.Substring(idx + 1) : String.Empty;

            name = checkName(name, "header");
            val = checkValue(val, "header");

            var headerType = getHeaderType(name);

            checkRestricted(name, headerType);
            checkAllowed(headerType);

            add(name, val, headerType);
        }

        /// <summary>
        /// Adds the specified request header with the specified value to
        /// the collection.
        /// </summary>
        /// <param name="header">
        ///   <para>
        ///   One of the <see cref="HttpRequestHeader"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the request header to add.
        ///   </para>
        /// </param>
        /// <param name="value">
        /// A <see cref="string"/> that specifies the value of the header to add.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="value"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="header"/> is a restricted header.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of <paramref name="value"/> is greater than 65,535
        /// characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the request header.
        /// </exception>
        public void Add(HttpRequestHeader header, string value)
        {
            value = checkValue(value, "value");

            var key = header.ToString();
            var name = getHeaderName(key);

            checkRestricted(name, HttpHeaderType.Request);
            checkAllowed(HttpHeaderType.Request);

            add(name, value, HttpHeaderType.Request);
        }

        /// <summary>
        /// Adds the specified response header with the specified value to
        /// the collection.
        /// </summary>
        /// <param name="header">
        ///   <para>
        ///   One of the <see cref="HttpResponseHeader"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the response header to add.
        ///   </para>
        /// </param>
        /// <param name="value">
        /// A <see cref="string"/> that specifies the value of the header to add.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="value"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="header"/> is a restricted header.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of <paramref name="value"/> is greater than 65,535
        /// characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the response header.
        /// </exception>
        public void Add(HttpResponseHeader header, string value)
        {
            value = checkValue(value, "value");

            var key = header.ToString();
            var name = getHeaderName(key);

            checkRestricted(name, HttpHeaderType.Response);
            checkAllowed(HttpHeaderType.Response);

            add(name, value, HttpHeaderType.Response);
        }

        /// <summary>
        /// Adds a header with the specified name and value to the collection.
        /// </summary>
        /// <param name="name">
        /// A <see cref="string"/> that specifies the name of the header to add.
        /// </param>
        /// <param name="value">
        /// A <see cref="string"/> that specifies the value of the header to add.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="name"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> is a string of spaces.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="value"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> is a restricted header name.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="name"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of <paramref name="value"/> is greater than 65,535
        /// characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the header.
        /// </exception>
        public override void Add(string name, string value)
        {
            name = checkName(name, "name");
            value = checkValue(value, "value");

            var headerType = getHeaderType(name);

            checkRestricted(name, headerType);
            checkAllowed(headerType);

            add(name, value, headerType);
        }

        /// <summary>
        /// Removes all headers from the collection.
        /// </summary>
        public override void Clear()
        {
            base.Clear();

            _state = HttpHeaderType.Unspecified;
        }

        /// <summary>
        /// Get the value of the header at the specified index in the collection.
        /// </summary>
        /// <returns>
        /// A <see cref="string"/> that receives the value of the header.
        /// </returns>
        /// <param name="index">
        /// An <see cref="int"/> that specifies the zero-based index of the header
        /// to get.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="index"/> is out of allowable range of indexes for
        /// the collection.
        /// </exception>
        public override string Get(int index)
        {
            return base.Get(index);
        }

        /// <summary>
        /// Get the value of the header with the specified name in the collection.
        /// </summary>
        /// <returns>
        ///   <para>
        ///   A <see cref="string"/> that receives the value of the header.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not found.
        ///   </para>
        /// </returns>
        /// <param name="name">
        /// A <see cref="string"/> that specifies the name of the header to get.
        /// </param>
        public override string Get(string name)
        {
            return base.Get(name);
        }

        /// <summary>
        /// Gets the enumerator used to iterate through the collection.
        /// </summary>
        /// <returns>
        /// An <see cref="IEnumerator"/> instance used to iterate through
        /// the collection.
        /// </returns>
        public override IEnumerator GetEnumerator()
        {
            return base.GetEnumerator();
        }

        /// <summary>
        /// Get the name of the header at the specified index in the collection.
        /// </summary>
        /// <returns>
        /// A <see cref="string"/> that receives the name of the header.
        /// </returns>
        /// <param name="index">
        /// An <see cref="int"/> that specifies the zero-based index of the header
        /// to get.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="index"/> is out of allowable range of indexes for
        /// the collection.
        /// </exception>
        public override string GetKey(int index)
        {
            return base.GetKey(index);
        }

        /// <summary>
        /// Get the values of the header at the specified index in the collection.
        /// </summary>
        /// <returns>
        ///   <para>
        ///   An array of <see cref="string"/> that receives the values of
        ///   the header.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not present.
        ///   </para>
        /// </returns>
        /// <param name="index">
        /// An <see cref="int"/> that specifies the zero-based index of the header
        /// to get.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="index"/> is out of allowable range of indexes for
        /// the collection.
        /// </exception>
        public override string[] GetValues(int index)
        {
            var vals = base.GetValues(index);

            return vals != null && vals.Length > 0 ? vals : null;
        }

        /// <summary>
        /// Get the values of the header with the specified name in the collection.
        /// </summary>
        /// <returns>
        ///   <para>
        ///   An array of <see cref="string"/> that receives the values of
        ///   the header.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not present.
        ///   </para>
        /// </returns>
        /// <param name="name">
        /// A <see cref="string"/> that specifies the name of the header to get.
        /// </param>
        public override string[] GetValues(string name)
        {
            var vals = base.GetValues(name);

            return vals != null && vals.Length > 0 ? vals : null;
        }

        /// <summary>
        /// Populates the specified <see cref="SerializationInfo"/> instance with
        /// the data needed to serialize the current instance.
        /// </summary>
        /// <param name="serializationInfo">
        /// A <see cref="SerializationInfo"/> that holds the serialized object data.
        /// </param>
        /// <param name="streamingContext">
        /// A <see cref="StreamingContext"/> that specifies the destination for
        /// the serialization.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="serializationInfo"/> is <see langword="null"/>.
        /// </exception>
        [
          SecurityPermission(
            SecurityAction.LinkDemand,
            Flags = SecurityPermissionFlag.SerializationFormatter
          )
        ]
        public override void GetObjectData(
          SerializationInfo serializationInfo,
          StreamingContext streamingContext
        )
        {
            if (serializationInfo == null)
                throw new ArgumentNullException("serializationInfo");

            serializationInfo.AddValue("InternallyUsed", _internallyUsed);
            serializationInfo.AddValue("State", (int)_state);

            var cnt = Count;

            serializationInfo.AddValue("Count", cnt);

            for (var i = 0; i < cnt; i++)
            {
                serializationInfo.AddValue(i.ToString(), GetKey(i));
                serializationInfo.AddValue((cnt + i).ToString(), Get(i));
            }
        }

        /// <summary>
        /// Determines whether the specified header can be set for the request.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the header cannot be set; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="headerName">
        /// A <see cref="string"/> that specifies the name of the header to test.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="headerName"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="headerName"/> is a string of spaces.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="headerName"/> contains an invalid character.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="headerName"/> is <see langword="null"/>.
        /// </exception>
        public static bool IsRestricted(string headerName)
        {
            return IsRestricted(headerName, false);
        }

        /// <summary>
        /// Determines whether the specified header can be set for the request or
        /// the response.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the header cannot be set; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="headerName">
        /// A <see cref="string"/> that specifies the name of the header to test.
        /// </param>
        /// <param name="response">
        /// A <see cref="bool"/>: <c>true</c> if the test is for the response;
        /// otherwise, <c>false</c>.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="headerName"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="headerName"/> is a string of spaces.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="headerName"/> contains an invalid character.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="headerName"/> is <see langword="null"/>.
        /// </exception>
        public static bool IsRestricted(string headerName, bool response)
        {
            headerName = checkName(headerName, "headerName");

            return isRestricted(headerName, response);
        }

        /// <summary>
        /// Implements the <see cref="ISerializable"/> interface and raises
        /// the deserialization event when the deserialization is complete.
        /// </summary>
        /// <param name="sender">
        /// An <see cref="object"/> instance that represents the source of
        /// the deserialization event.
        /// </param>
        public override void OnDeserialization(object sender)
        {
        }

        /// <summary>
        /// Removes the specified request header from the collection.
        /// </summary>
        /// <param name="header">
        ///   <para>
        ///   One of the <see cref="HttpRequestHeader"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the request header to remove.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="header"/> is a restricted header.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the request header.
        /// </exception>
        public void Remove(HttpRequestHeader header)
        {
            var key = header.ToString();
            var name = getHeaderName(key);

            checkRestricted(name, HttpHeaderType.Request);
            checkAllowed(HttpHeaderType.Request);

            base.Remove(name);
        }

        /// <summary>
        /// Removes the specified response header from the collection.
        /// </summary>
        /// <param name="header">
        ///   <para>
        ///   One of the <see cref="HttpResponseHeader"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the response header to remove.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="header"/> is a restricted header.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the response header.
        /// </exception>
        public void Remove(HttpResponseHeader header)
        {
            var key = header.ToString();
            var name = getHeaderName(key);

            checkRestricted(name, HttpHeaderType.Response);
            checkAllowed(HttpHeaderType.Response);

            base.Remove(name);
        }

        /// <summary>
        /// Removes the specified header from the collection.
        /// </summary>
        /// <param name="name">
        /// A <see cref="string"/> that specifies the name of the header to remove.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="name"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> is a string of spaces.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> is a restricted header name.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="name"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the header.
        /// </exception>
        public override void Remove(string name)
        {
            name = checkName(name, "name");

            var headerType = getHeaderType(name);

            checkRestricted(name, headerType);
            checkAllowed(headerType);

            base.Remove(name);
        }

        /// <summary>
        /// Sets the specified request header to the specified value.
        /// </summary>
        /// <param name="header">
        ///   <para>
        ///   One of the <see cref="HttpRequestHeader"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the request header to set.
        ///   </para>
        /// </param>
        /// <param name="value">
        /// A <see cref="string"/> that specifies the value of the request header
        /// to set.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="value"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="header"/> is a restricted header.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of <paramref name="value"/> is greater than 65,535
        /// characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the request header.
        /// </exception>
        public void Set(HttpRequestHeader header, string value)
        {
            value = checkValue(value, "value");

            var key = header.ToString();
            var name = getHeaderName(key);

            checkRestricted(name, HttpHeaderType.Request);
            checkAllowed(HttpHeaderType.Request);

            set(name, value, HttpHeaderType.Request);
        }

        /// <summary>
        /// Sets the specified response header to the specified value.
        /// </summary>
        /// <param name="header">
        ///   <para>
        ///   One of the <see cref="HttpResponseHeader"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the response header to set.
        ///   </para>
        /// </param>
        /// <param name="value">
        /// A <see cref="string"/> that specifies the value of the response header
        /// to set.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="value"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="header"/> is a restricted header.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of <paramref name="value"/> is greater than 65,535
        /// characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the response header.
        /// </exception>
        public void Set(HttpResponseHeader header, string value)
        {
            value = checkValue(value, "value");

            var key = header.ToString();
            var name = getHeaderName(key);

            checkRestricted(name, HttpHeaderType.Response);
            checkAllowed(HttpHeaderType.Response);

            set(name, value, HttpHeaderType.Response);
        }

        /// <summary>
        /// Sets the specified header to the specified value.
        /// </summary>
        /// <param name="name">
        /// A <see cref="string"/> that specifies the name of the header to set.
        /// </param>
        /// <param name="value">
        /// A <see cref="string"/> that specifies the value of the header to set.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="name"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> is a string of spaces.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="value"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="name"/> is a restricted header name.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="name"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The length of <paramref name="value"/> is greater than 65,535
        /// characters.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// This instance does not allow the header.
        /// </exception>
        public override void Set(string name, string value)
        {
            name = checkName(name, "name");
            value = checkValue(value, "value");

            var headerType = getHeaderType(name);

            checkRestricted(name, headerType);
            checkAllowed(headerType);

            set(name, value, headerType);
        }

        /// <summary>
        /// Converts the current instance to an array of byte.
        /// </summary>
        /// <returns>
        /// An array of <see cref="byte"/> converted from a string that represents
        /// the current instance.
        /// </returns>
        public byte[] ToByteArray()
        {
            var s = ToString();

            return Encoding.UTF8.GetBytes(s);
        }

        /// <summary>
        /// Returns a string that represents the current instance.
        /// </summary>
        /// <returns>
        /// A <see cref="string"/> that represents all headers in the collection.
        /// </returns>
        public override string ToString()
        {
            var cnt = Count;

            if (cnt == 0)
                return "\r\n";

            var buff = new StringBuilder();

            var fmt = "{0}: {1}\r\n";

            for (var i = 0; i < cnt; i++)
                buff.AppendFormat(fmt, GetKey(i), Get(i));

            buff.Append("\r\n");

            return buff.ToString();
        }

        /// <summary>
        /// Populates the specified <see cref="SerializationInfo"/> instance with
        /// the data needed to serialize the current instance.
        /// </summary>
        /// <param name="serializationInfo">
        /// A <see cref="SerializationInfo"/> that holds the serialized object data.
        /// </param>
        /// <param name="streamingContext">
        /// A <see cref="StreamingContext"/> that specifies the destination for
        /// the serialization.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="serializationInfo"/> is <see langword="null"/>.
        /// </exception>
        [
          SecurityPermission(
            SecurityAction.LinkDemand,
            Flags = SecurityPermissionFlag.SerializationFormatter,
            SerializationFormatter = true
          )
        ]
        void ISerializable.GetObjectData(
          SerializationInfo serializationInfo,
          StreamingContext streamingContext
        )
        {
            GetObjectData(serializationInfo, streamingContext);
        }
    }
    //==================================================================================










}
