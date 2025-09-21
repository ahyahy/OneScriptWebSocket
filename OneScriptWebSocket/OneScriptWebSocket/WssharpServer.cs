using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Principal;
using System.Net.Sockets;
using System.Threading;
using System.Collections;
using System.Collections.Specialized;
using WebSocketSharp.Net;
using WebSocketSharp.Net.WebSockets;

namespace WebSocketSharp.Server
{
    /// <summary>
    /// Represents the event data for the HTTP request events of the
    /// <see cref="HttpServer"/> class.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///   An HTTP request event occurs when the <see cref="HttpServer"/>
    ///   instance receives an HTTP request.
    ///   </para>
    ///   <para>
    ///   You should access the <see cref="Request"/> property if you would
    ///   like to get the request data sent from a client.
    ///   </para>
    ///   <para>
    ///   And you should access the <see cref="Response"/> property if you
    ///   would like to get the response data to return to the client.
    ///   </para>
    /// </remarks>
    public class HttpRequestEventArgs : EventArgs
    {
        private HttpListenerContext _context;
        private string _docRootPath;

        internal HttpRequestEventArgs(
          HttpListenerContext context,
          string documentRootPath
        )
        {
            _context = context;
            _docRootPath = documentRootPath;
        }

        /// <summary>
        /// Gets the request data sent from a client.
        /// </summary>
        /// <value>
        /// A <see cref="HttpListenerRequest"/> that provides the methods and
        /// properties for the request data.
        /// </value>
        public HttpListenerRequest Request
        {
            get
            {
                return _context.Request;
            }
        }

        /// <summary>
        /// Gets the response data to return to the client.
        /// </summary>
        /// <value>
        /// A <see cref="HttpListenerResponse"/> that provides the methods and
        /// properties for the response data.
        /// </value>
        public HttpListenerResponse Response
        {
            get
            {
                return _context.Response;
            }
        }

        /// <summary>
        /// Gets the information for the client.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="IPrincipal"/> instance that represents identity,
        ///   authentication scheme, and security roles for the client.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the client is not authenticated.
        ///   </para>
        /// </value>
        public IPrincipal User
        {
            get
            {
                return _context.User;
            }
        }

        private string createFilePath(string childPath)
        {
            childPath = childPath.TrimStart('/', '\\');

            return new StringBuilder(_docRootPath, 32)
                   .AppendFormat("/{0}", childPath)
                   .ToString()
                   .Replace('\\', '/');
        }

        private static bool tryReadFile(string path, out byte[] contents)
        {
            contents = null;

            if (!File.Exists(path))
                return false;

            try
            {
                contents = File.ReadAllBytes(path);
            }
            catch
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Reads the specified file from the document folder of the
        /// <see cref="HttpServer"/> class.
        /// </summary>
        /// <returns>
        ///   <para>
        ///   An array of <see cref="byte"/> that receives the contents of
        ///   the file.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the read has failed.
        ///   </para>
        /// </returns>
        /// <param name="path">
        /// A <see cref="string"/> that specifies a virtual path to find
        /// the file from the document folder.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> contains "..".
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public byte[] ReadFile(string path)
        {
            if (path == null)
                throw new ArgumentNullException("path");

            if (path.Length == 0)
                throw new ArgumentException("An empty string.", "path");

            if (path.Contains(".."))
            {
                var msg = "It contains \"..\".";

                throw new ArgumentException(msg, "path");
            }

            path = createFilePath(path);
            byte[] contents;

            tryReadFile(path, out contents);

            return contents;
        }

        /// <summary>
        /// Tries to read the specified file from the document folder of
        /// the <see cref="HttpServer"/> class.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the try has succeeded; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="path">
        /// A <see cref="string"/> that specifies a virtual path to find
        /// the file from the document folder.
        /// </param>
        /// <param name="contents">
        ///   <para>
        ///   When this method returns, an array of <see cref="byte"/> that
        ///   receives the contents of the file.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the read has failed.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> contains "..".
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public bool TryReadFile(string path, out byte[] contents)
        {
            if (path == null)
                throw new ArgumentNullException("path");

            if (path.Length == 0)
                throw new ArgumentException("An empty string.", "path");

            if (path.Contains(".."))
            {
                var msg = "It contains \"..\".";

                throw new ArgumentException(msg, "path");
            }

            path = createFilePath(path);

            return tryReadFile(path, out contents);
        }
    }
    //================================================================================
    /// <summary>
    /// Provides a simple HTTP server.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///   The server supports HTTP/1.1 version request and response.
    ///   </para>
    ///   <para>
    ///   Also the server allows to accept WebSocket handshake requests.
    ///   </para>
    ///   <para>
    ///   This class can provide multiple WebSocket services.
    ///   </para>
    /// </remarks>
    public class HttpServer
    {

        private System.Net.IPAddress _address;
        private string _docRootPath;
        private bool _isSecure;
        private HttpListener _listener;
        private Logger _log;
        private int _port;
        private Thread _receiveThread;
        private WebSocketServiceManager _services;
        private volatile ServerState _state;
        private object _sync;

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpServer"/> class.
        /// </summary>
        /// <remarks>
        /// The new instance listens for incoming requests on
        /// <see cref="System.Net.IPAddress.Any"/> and port 80.
        /// </remarks>
        public HttpServer()
        {
            init("*", System.Net.IPAddress.Any, 80, false);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpServer"/> class with
        /// the specified port.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   The new instance listens for incoming requests on
        ///   <see cref="System.Net.IPAddress.Any"/> and <paramref name="port"/>.
        ///   </para>
        ///   <para>
        ///   It provides secure connections if <paramref name="port"/> is 443.
        ///   </para>
        /// </remarks>
        /// <param name="port">
        /// An <see cref="int"/> that specifies the number of the port on which
        /// to listen.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="port"/> is less than 1 or greater than 65535.
        /// </exception>
        public HttpServer(int port)
          : this(port, port == 443)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpServer"/> class with
        /// the specified URL.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   The new instance listens for incoming requests on the IP address and
        ///   port of <paramref name="url"/>.
        ///   </para>
        ///   <para>
        ///   Either port 80 or 443 is used if <paramref name="url"/> includes
        ///   no port. Port 443 is used if the scheme of <paramref name="url"/>
        ///   is https; otherwise, port 80 is used.
        ///   </para>
        ///   <para>
        ///   The new instance provides secure connections if the scheme of
        ///   <paramref name="url"/> is https.
        ///   </para>
        /// </remarks>
        /// <param name="url">
        /// A <see cref="string"/> that specifies the HTTP URL of the server.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="url"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="url"/> is invalid.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="url"/> is <see langword="null"/>.
        /// </exception>
        public HttpServer(string url)
        {
            if (url == null)
                throw new ArgumentNullException("url");

            if (url.Length == 0)
                throw new ArgumentException("An empty string.", "url");

            Uri uri;
            string msg;

            if (!tryCreateUri(url, out uri, out msg))
                throw new ArgumentException(msg, "url");

            var host = uri.GetDnsSafeHost(true);
            var addr = host.ToIPAddress();

            if (addr == null)
            {
                msg = "The host part could not be converted to an IP address.";

                throw new ArgumentException(msg, "url");
            }

            if (!addr.IsLocal())
            {
                msg = "The IP address of the host is not a local IP address.";

                throw new ArgumentException(msg, "url");
            }

            init(host, addr, uri.Port, uri.Scheme == "https");
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpServer"/> class with
        /// the specified port and boolean if secure or not.
        /// </summary>
        /// <remarks>
        /// The new instance listens for incoming requests on
        /// <see cref="System.Net.IPAddress.Any"/> and <paramref name="port"/>.
        /// </remarks>
        /// <param name="port">
        /// An <see cref="int"/> that specifies the number of the port on which
        /// to listen.
        /// </param>
        /// <param name="secure">
        /// A <see cref="bool"/>: <c>true</c> if the new instance provides
        /// secure connections; otherwise, <c>false</c>.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="port"/> is less than 1 or greater than 65535.
        /// </exception>
        public HttpServer(int port, bool secure)
        {
            if (!port.IsPortNumber())
            {
                var msg = "Less than 1 or greater than 65535.";

                throw new ArgumentOutOfRangeException("port", msg);
            }

            init("*", System.Net.IPAddress.Any, port, secure);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpServer"/> class with
        /// the specified IP address and port.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   The new instance listens for incoming requests on
        ///   <paramref name="address"/> and <paramref name="port"/>.
        ///   </para>
        ///   <para>
        ///   It provides secure connections if <paramref name="port"/> is 443.
        ///   </para>
        /// </remarks>
        /// <param name="address">
        /// A <see cref="System.Net.IPAddress"/> that specifies the local IP
        /// address on which to listen.
        /// </param>
        /// <param name="port">
        /// An <see cref="int"/> that specifies the number of the port on which
        /// to listen.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="address"/> is not a local IP address.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="address"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="port"/> is less than 1 or greater than 65535.
        /// </exception>
        public HttpServer(System.Net.IPAddress address, int port)
          : this(address, port, port == 443)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpServer"/> class with
        /// the specified IP address, port, and boolean if secure or not.
        /// </summary>
        /// <remarks>
        /// The new instance listens for incoming requests on
        /// <paramref name="address"/> and <paramref name="port"/>.
        /// </remarks>
        /// <param name="address">
        /// A <see cref="System.Net.IPAddress"/> that specifies the local IP
        /// address on which to listen.
        /// </param>
        /// <param name="port">
        /// An <see cref="int"/> that specifies the number of the port on which
        /// to listen.
        /// </param>
        /// <param name="secure">
        /// A <see cref="bool"/>: <c>true</c> if the new instance provides
        /// secure connections; otherwise, <c>false</c>.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="address"/> is not a local IP address.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="address"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="port"/> is less than 1 or greater than 65535.
        /// </exception>
        public HttpServer(System.Net.IPAddress address, int port, bool secure)
        {
            if (address == null)
                throw new ArgumentNullException("address");

            if (!address.IsLocal())
            {
                var msg = "Not a local IP address.";

                throw new ArgumentException(msg, "address");
            }

            if (!port.IsPortNumber())
            {
                var msg = "Less than 1 or greater than 65535.";

                throw new ArgumentOutOfRangeException("port", msg);
            }

            init(address.ToString(true), address, port, secure);
        }

        /// <summary>
        /// Gets the IP address of the server.
        /// </summary>
        /// <value>
        /// A <see cref="System.Net.IPAddress"/> that represents the local IP
        /// address on which to listen for incoming requests.
        /// </value>
        public System.Net.IPAddress Address
        {
            get
            {
                return _address;
            }
        }

        /// <summary>
        /// Gets or sets the scheme used to authenticate the clients.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
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
        public AuthenticationSchemes AuthenticationSchemes
        {
            get
            {
                return _listener.AuthenticationSchemes;
            }

            set
            {
                lock (_sync)
                {
                    if (!canSet())
                        return;

                    _listener.AuthenticationSchemes = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the path to the document folder of the server.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents a path to the folder
        ///   from which to find the requested file.
        ///   </para>
        ///   <para>
        ///   / or \ is trimmed from the end of the value if present.
        ///   </para>
        ///   <para>
        ///   The default value is "./Public".
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
        ///   The value specified for a set operation is an absolute root.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The value specified for a set operation is an invalid path string.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// The value specified for a set operation is <see langword="null"/>.
        /// </exception>
        public string DocumentRootPath
        {
            get
            {
                return _docRootPath;
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                if (value.Length == 0)
                    throw new ArgumentException("An empty string.", "value");

                value = value.TrimSlashOrBackslashFromEnd();

                if (value == "/")
                    throw new ArgumentException("An absolute root.", "value");

                if (value == "\\")
                    throw new ArgumentException("An absolute root.", "value");

                if (value.Length == 2 && value[1] == ':')
                    throw new ArgumentException("An absolute root.", "value");

                string full = null;

                try
                {
                    full = Path.GetFullPath(value);
                }
                catch (Exception ex)
                {
                    throw new ArgumentException("An invalid path string.", "value", ex);
                }

                if (full == "/")
                    throw new ArgumentException("An absolute root.", "value");

                full = full.TrimSlashOrBackslashFromEnd();

                if (full.Length == 2 && full[1] == ':')
                    throw new ArgumentException("An absolute root.", "value");

                lock (_sync)
                {
                    if (!canSet())
                        return;

                    _docRootPath = value;
                }
            }
        }

        /// <summary>
        /// Gets a value indicating whether the server has started.
        /// </summary>
        /// <value>
        /// <c>true</c> if the server has started; otherwise, <c>false</c>.
        /// </value>
        public bool IsListening
        {
            get
            {
                return _state == ServerState.Start;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the server provides secure connections.
        /// </summary>
        /// <value>
        /// <c>true</c> if the server provides secure connections; otherwise,
        /// <c>false</c>.
        /// </value>
        public bool IsSecure
        {
            get
            {
                return _isSecure;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the server cleans up
        /// the inactive sessions periodically.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the server cleans up the inactive sessions
        ///   every 60 seconds; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool KeepClean
        {
            get
            {
                return _services.KeepClean;
            }

            set
            {
                _services.KeepClean = value;
            }
        }

        /// <summary>
        /// Gets the logging function for the server.
        /// </summary>
        /// <remarks>
        /// The default logging level is <see cref="LogLevel.Error"/>.
        /// </remarks>
        /// <value>
        /// A <see cref="Logger"/> that provides the logging function.
        /// </value>
        public Logger Log
        {
            get
            {
                return _log;
            }
        }

        /// <summary>
        /// Gets the port of the server.
        /// </summary>
        /// <value>
        /// An <see cref="int"/> that represents the number of the port on which
        /// to listen for incoming requests.
        /// </value>
        public int Port
        {
            get
            {
                return _port;
            }
        }

        /// <summary>
        /// Gets or sets the name of the realm associated with the server.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the name of the realm.
        ///   </para>
        ///   <para>
        ///   "SECRET AREA" is used as the name of the realm if the value is
        ///   <see langword="null"/> or an empty string.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        public string Realm
        {
            get
            {
                return _listener.Realm;
            }

            set
            {
                lock (_sync)
                {
                    if (!canSet())
                        return;

                    _listener.Realm = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the server is allowed to
        /// be bound to an address that is already in use.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   You should set this property to <c>true</c> if you would like to
        ///   resolve to wait for socket in TIME_WAIT state.
        ///   </para>
        ///   <para>
        ///   The set operation works if the current state of the server is
        ///   Ready or Stop.
        ///   </para>
        /// </remarks>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the server is allowed to be bound to an address
        ///   that is already in use; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool ReuseAddress
        {
            get
            {
                return _listener.ReuseAddress;
            }

            set
            {
                lock (_sync)
                {
                    if (!canSet())
                        return;

                    _listener.ReuseAddress = value;
                }
            }
        }

        /// <summary>
        /// Gets the configuration for secure connection.
        /// </summary>
        /// <remarks>
        /// The configuration is used when the server attempts to start,
        /// so it must be configured before the start method is called.
        /// </remarks>
        /// <value>
        /// A <see cref="ServerSslConfiguration"/> that represents the
        /// configuration used to provide secure connections.
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The server does not provide secure connections.
        /// </exception>
        public ServerSslConfiguration SslConfiguration
        {
            get
            {
                if (!_isSecure)
                {
                    var msg = "The server does not provide secure connections.";

                    throw new InvalidOperationException(msg);
                }

                return _listener.SslConfiguration;
            }
        }

        /// <summary>
        /// Gets or sets the delegate called to find the credentials for
        /// an identity used to authenticate a client.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="T:System.Func{IIdentity, NetworkCredential}"/>
        ///   delegate.
        ///   </para>
        ///   <para>
        ///   It represents the delegate called when the server finds
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
        public Func<IIdentity, NetworkCredential> UserCredentialsFinder
        {
            get
            {
                return _listener.UserCredentialsFinder;
            }

            set
            {
                lock (_sync)
                {
                    if (!canSet())
                        return;

                    _listener.UserCredentialsFinder = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the time to wait for the response to the WebSocket
        /// Ping or Close.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="TimeSpan"/> that represents the time to wait for
        ///   the response.
        ///   </para>
        ///   <para>
        ///   The default value is the same as 1 second.
        ///   </para>
        /// </value>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The value specified for a set operation is zero or less.
        /// </exception>
        public TimeSpan WaitTime
        {
            get
            {
                return _services.WaitTime;
            }

            set
            {
                _services.WaitTime = value;
            }
        }

        /// <summary>
        /// Gets the management function for the WebSocket services provided by
        /// the server.
        /// </summary>
        /// <value>
        /// A <see cref="WebSocketServiceManager"/> that manages the WebSocket
        /// services provided by the server.
        /// </value>
        public WebSocketServiceManager WebSocketServices
        {
            get
            {
                return _services;
            }
        }

        /// <summary>
        /// Occurs when the server receives an HTTP CONNECT request.
        /// </summary>
        public event EventHandler<HttpRequestEventArgs> OnConnect;

        /// <summary>
        /// Occurs when the server receives an HTTP DELETE request.
        /// </summary>
        public event EventHandler<HttpRequestEventArgs> OnDelete;

        /// <summary>
        /// Occurs when the server receives an HTTP GET request.
        /// </summary>
        public event EventHandler<HttpRequestEventArgs> OnGet;

        /// <summary>
        /// Occurs when the server receives an HTTP HEAD request.
        /// </summary>
        public event EventHandler<HttpRequestEventArgs> OnHead;

        /// <summary>
        /// Occurs when the server receives an HTTP OPTIONS request.
        /// </summary>
        public event EventHandler<HttpRequestEventArgs> OnOptions;

        /// <summary>
        /// Occurs when the server receives an HTTP POST request.
        /// </summary>
        public event EventHandler<HttpRequestEventArgs> OnPost;

        /// <summary>
        /// Occurs when the server receives an HTTP PUT request.
        /// </summary>
        public event EventHandler<HttpRequestEventArgs> OnPut;

        /// <summary>
        /// Occurs when the server receives an HTTP TRACE request.
        /// </summary>
        public event EventHandler<HttpRequestEventArgs> OnTrace;

        private void abort()
        {
            lock (_sync)
            {
                if (_state != ServerState.Start)
                    return;

                _state = ServerState.ShuttingDown;
            }

            try
            {
                _services.Stop(1006, String.Empty);
            }
            catch (Exception ex)
            {
                _log.Fatal(ex.Message);
                _log.Debug(ex.ToString());
            }

            try
            {
                _listener.Abort();
            }
            catch (Exception ex)
            {
                _log.Fatal(ex.Message);
                _log.Debug(ex.ToString());
            }

            _state = ServerState.Stop;
        }

        private bool canSet()
        {
            return _state == ServerState.Ready || _state == ServerState.Stop;
        }

        private bool checkCertificate(out string message)
        {
            message = null;

            var byUser = _listener.SslConfiguration.ServerCertificate != null;

            var path = _listener.CertificateFolderPath;
            var withPort = EndPointListener.CertificateExists(_port, path);

            var either = byUser || withPort;

            if (!either)
            {
                message = "There is no server certificate for secure connection.";

                return false;
            }

            var both = byUser && withPort;

            if (both)
            {
                var msg = "The server certificate associated with the port is used.";

                _log.Warn(msg);
            }

            return true;
        }

        private static HttpListener createListener(
          string hostname,
          int port,
          bool secure
        )
        {
            var ret = new HttpListener();

            var fmt = "{0}://{1}:{2}/";
            var schm = secure ? "https" : "http";
            var pref = String.Format(fmt, schm, hostname, port);

            ret.Prefixes.Add(pref);

            return ret;
        }

        private void init(
          string hostname,
          System.Net.IPAddress address,
          int port,
          bool secure
        )
        {
            _address = address;
            _port = port;
            _isSecure = secure;

            _docRootPath = "./Public";
            _listener = createListener(hostname, port, secure);
            _log = _listener.Log;
            _services = new WebSocketServiceManager(_log);
            _sync = new object();
        }

        private void processRequest(HttpListenerContext context)
        {
            var method = context.Request.HttpMethod;
            var evt = method == "GET"
                      ? OnGet
                      : method == "HEAD"
                        ? OnHead
                        : method == "POST"
                          ? OnPost
                          : method == "PUT"
                            ? OnPut
                            : method == "DELETE"
                              ? OnDelete
                              : method == "CONNECT"
                                ? OnConnect
                                : method == "OPTIONS"
                                  ? OnOptions
                                  : method == "TRACE"
                                    ? OnTrace
                                    : null;

            if (evt == null)
            {
                context.ErrorStatusCode = 501;

                context.SendError();

                return;
            }

            var e = new HttpRequestEventArgs(context, _docRootPath);

            evt(this, e);

            context.Response.Close();
        }

        private void processRequest(HttpListenerWebSocketContext context)
        {
            var uri = context.RequestUri;

            if (uri == null)
            {
                context.Close(HttpStatusCode.BadRequest);

                return;
            }

            var path = uri.AbsolutePath;

            if (path.IndexOfAny(new[] { '%', '+' }) > -1)
                path = HttpUtility.UrlDecode(path, Encoding.UTF8);

            WebSocketServiceHost host;

            if (!_services.InternalTryGetServiceHost(path, out host))
            {
                context.Close(HttpStatusCode.NotImplemented);

                return;
            }

            host.StartSession(context);
        }

        private void receiveRequest()
        {
            while (true)
            {
                HttpListenerContext ctx = null;

                try
                {
                    ctx = _listener.GetContext();

                    ThreadPool.QueueUserWorkItem(
                      state => {
                          try
                          {
                              if (ctx.Request.IsUpgradeRequest("websocket"))
                              {
                                  processRequest(ctx.GetWebSocketContext(null));

                                  return;
                              }

                              processRequest(ctx);
                          }
                          catch (Exception ex)
                          {
                              _log.Error(ex.Message);
                              _log.Debug(ex.ToString());

                              ctx.Connection.Close(true);
                          }
                      }
                    );
                }
                catch (HttpListenerException ex)
                {
                    if (_state == ServerState.ShuttingDown)
                        return;

                    _log.Fatal(ex.Message);
                    _log.Debug(ex.ToString());

                    break;
                }
                catch (InvalidOperationException ex)
                {
                    if (_state == ServerState.ShuttingDown)
                        return;

                    _log.Fatal(ex.Message);
                    _log.Debug(ex.ToString());

                    break;
                }
                catch (Exception ex)
                {
                    _log.Fatal(ex.Message);
                    _log.Debug(ex.ToString());

                    if (ctx != null)
                        ctx.Connection.Close(true);

                    if (_state == ServerState.ShuttingDown)
                        return;

                    break;
                }
            }

            abort();
        }

        private void start()
        {
            lock (_sync)
            {
                if (_state == ServerState.Start || _state == ServerState.ShuttingDown)
                    return;

                if (_isSecure)
                {
                    string msg;

                    if (!checkCertificate(out msg))
                        throw new InvalidOperationException(msg);
                }

                _services.Start();

                try
                {
                    startReceiving();
                }
                catch
                {
                    _services.Stop(1011, String.Empty);

                    throw;
                }

                _state = ServerState.Start;
            }
        }

        private void startReceiving()
        {
            try
            {
                _listener.Start();
            }
            catch (Exception ex)
            {
                var msg = "The underlying listener has failed to start.";

                throw new InvalidOperationException(msg, ex);
            }

            var receiver = new ThreadStart(receiveRequest);
            _receiveThread = new Thread(receiver);
            _receiveThread.IsBackground = true;

            _receiveThread.Start();
        }

        private void stop(ushort code, string reason)
        {
            lock (_sync)
            {
                if (_state != ServerState.Start)
                    return;

                _state = ServerState.ShuttingDown;
            }

            try
            {
                _services.Stop(code, reason);
            }
            catch (Exception ex)
            {
                _log.Fatal(ex.Message);
                _log.Debug(ex.ToString());
            }

            try
            {
                var timeout = 5000;

                stopReceiving(timeout);
            }
            catch (Exception ex)
            {
                _log.Fatal(ex.Message);
                _log.Debug(ex.ToString());
            }

            _state = ServerState.Stop;
        }

        private void stopReceiving(int millisecondsTimeout)
        {
            _listener.Stop();
            _receiveThread.Join(millisecondsTimeout);
        }

        private static bool tryCreateUri(
          string uriString,
          out Uri result,
          out string message
        )
        {
            result = null;
            message = null;

            var uri = uriString.ToUri();

            if (uri == null)
            {
                message = "An invalid URI string.";

                return false;
            }

            if (!uri.IsAbsoluteUri)
            {
                message = "A relative URI.";

                return false;
            }

            var schm = uri.Scheme;
            var isHttpSchm = schm == "http" || schm == "https";

            if (!isHttpSchm)
            {
                message = "The scheme part is not 'http' or 'https'.";

                return false;
            }

            if (uri.PathAndQuery != "/")
            {
                message = "It includes either or both path and query components.";

                return false;
            }

            if (uri.Fragment.Length > 0)
            {
                message = "It includes the fragment component.";

                return false;
            }

            if (uri.Port == 0)
            {
                message = "The port part is zero.";

                return false;
            }

            result = uri;

            return true;
        }

        /// <summary>
        /// Adds a WebSocket service with the specified behavior and path.
        /// </summary>
        /// <param name="path">
        ///   <para>
        ///   A <see cref="string"/> that specifies an absolute path to
        ///   the service to add.
        ///   </para>
        ///   <para>
        ///   / is trimmed from the end of the string if present.
        ///   </para>
        /// </param>
        /// <typeparam name="TBehavior">
        ///   <para>
        ///   The type of the behavior for the service.
        ///   </para>
        ///   <para>
        ///   It must inherit the <see cref="WebSocketBehavior"/> class.
        ///   </para>
        ///   <para>
        ///   Also it must have a public parameterless constructor.
        ///   </para>
        /// </typeparam>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is not an absolute path.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> includes either or both
        ///   query and fragment components.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is already in use.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public void AddWebSocketService<TBehavior>(string path)
          where TBehavior : WebSocketBehavior, new()
        {
            _services.AddService<TBehavior>(path, null);
        }

        /// <summary>
        /// Adds a WebSocket service with the specified behavior, path,
        /// and initializer.
        /// </summary>
        /// <param name="path">
        ///   <para>
        ///   A <see cref="string"/> that specifies an absolute path to
        ///   the service to add.
        ///   </para>
        ///   <para>
        ///   / is trimmed from the end of the string if present.
        ///   </para>
        /// </param>
        /// <param name="initializer">
        ///   <para>
        ///   An <see cref="T:System.Action{TBehavior}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the service initializes
        ///   a new session instance.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <typeparam name="TBehavior">
        ///   <para>
        ///   The type of the behavior for the service.
        ///   </para>
        ///   <para>
        ///   It must inherit the <see cref="WebSocketBehavior"/> class.
        ///   </para>
        ///   <para>
        ///   Also it must have a public parameterless constructor.
        ///   </para>
        /// </typeparam>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is not an absolute path.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> includes either or both
        ///   query and fragment components.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is already in use.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public void AddWebSocketService<TBehavior>(
          string path,
          Action<TBehavior> initializer
        )
          where TBehavior : WebSocketBehavior, new()
        {
            _services.AddService<TBehavior>(path, initializer);
        }

        /// <summary>
        /// Removes a WebSocket service with the specified path.
        /// </summary>
        /// <remarks>
        /// The service is stopped with close status 1001 (going away)
        /// if the current state of the service is Start.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if the service is successfully found and removed;
        /// otherwise, <c>false</c>.
        /// </returns>
        /// <param name="path">
        ///   <para>
        ///   A <see cref="string"/> that specifies an absolute path to
        ///   the service to remove.
        ///   </para>
        ///   <para>
        ///   / is trimmed from the end of the string if present.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is not an absolute path.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> includes either or both
        ///   query and fragment components.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public bool RemoveWebSocketService(string path)
        {
            return _services.RemoveService(path);
        }

        /// <summary>
        /// Starts receiving incoming requests.
        /// </summary>
        /// <remarks>
        /// This method works if the current state of the server is Ready or Stop.
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   There is no server certificate for secure connection.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The underlying <see cref="HttpListener"/> has failed to start.
        ///   </para>
        /// </exception>
        public void Start()
        {
            if (_state == ServerState.Start || _state == ServerState.ShuttingDown)
                return;

            start();
        }

        /// <summary>
        /// Stops receiving incoming requests.
        /// </summary>
        /// <remarks>
        /// This method works if the current state of the server is Start.
        /// </remarks>
        public void Stop()
        {
            if (_state != ServerState.Start)
                return;

            stop(1001, String.Empty);
        }
    }
    //=====================================================================================
    /// <summary>
    /// Exposes the access to the information in a WebSocket session.
    /// </summary>
    public interface IWebSocketSession
    {
        /// <summary>
        /// Gets the unique ID of the session.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the unique ID of the session.
        /// </value>
        string ID { get; }

        /// <summary>
        /// Gets the time that the session has started.
        /// </summary>
        /// <value>
        /// A <see cref="DateTime"/> that represents the time that the session
        /// has started.
        /// </value>
        DateTime StartTime { get; }

        /// <summary>
        /// Gets the WebSocket interface for the session.
        /// </summary>
        /// <value>
        /// A <see cref="WebSocketSharp.WebSocket"/> that represents the interface.
        /// </value>
        WebSocket WebSocket { get; }
    }
    //===============================================================================
    internal enum ServerState
    {
        Ready,
        Start,
        ShuttingDown,
        Stop
    }
    //===============================================================================
    /// <summary>
    /// Exposes a set of methods and properties used to define the behavior of
    /// a WebSocket service provided by the <see cref="WebSocketServer"/> or
    /// <see cref="HttpServer"/> class.
    /// </summary>
    /// <remarks>
    /// This class is an abstract class.
    /// </remarks>
    public abstract class WebSocketBehavior : IWebSocketSession
    {
        private WebSocketContext _context;
        private Func<CookieCollection, CookieCollection, bool> _cookiesValidator;
        private bool _emitOnPing;
        private Func<string, bool> _hostValidator;
        private string _id;
        private bool _ignoreExtensions;
        private bool _noDelay;
        private Func<string, bool> _originValidator;
        private string _protocol;
        private WebSocketSessionManager _sessions;
        private DateTime _startTime;
        private WebSocket _websocket;

        /// <summary>
        /// Initializes a new instance of the <see cref="WebSocketBehavior"/> class.
        /// </summary>
        protected WebSocketBehavior()
        {
            _startTime = DateTime.MaxValue;
        }

        /// <summary>
        /// Gets the HTTP headers for a session.
        /// </summary>
        /// <value>
        /// A <see cref="NameValueCollection"/> that contains the headers
        /// included in the WebSocket handshake request.
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected NameValueCollection Headers
        {
            get
            {
                if (_context == null)
                {
                    var msg = "The session has not started yet.";

                    throw new InvalidOperationException(msg);
                }

                return _context.Headers;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the communication is possible for
        /// a session.
        /// </summary>
        /// <value>
        /// <c>true</c> if the communication is possible; otherwise, <c>false</c>.
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected bool IsAlive
        {
            get
            {
                if (_websocket == null)
                {
                    var msg = "The session has not started yet.";

                    throw new InvalidOperationException(msg);
                }

                return _websocket.IsAlive;
            }
        }

        /// <summary>
        /// Gets the query string for a session.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="NameValueCollection"/> that contains the query
        ///   parameters included in the WebSocket handshake request.
        ///   </para>
        ///   <para>
        ///   An empty collection if not included.
        ///   </para>
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected NameValueCollection QueryString
        {
            get
            {
                if (_context == null)
                {
                    var msg = "The session has not started yet.";

                    throw new InvalidOperationException(msg);
                }

                return _context.QueryString;
            }
        }

        /// <summary>
        /// Gets the current state of the WebSocket interface for a session.
        /// </summary>
        /// <value>
        ///   <para>
        ///   One of the <see cref="WebSocketState"/> enum values.
        ///   </para>
        ///   <para>
        ///   It indicates the current state of the interface.
        ///   </para>
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected WebSocketState ReadyState
        {
            get
            {
                if (_websocket == null)
                {
                    var msg = "The session has not started yet.";

                    throw new InvalidOperationException(msg);
                }

                return _websocket.ReadyState;
            }
        }

        /// <summary>
        /// Gets the management function for the sessions in the service.
        /// </summary>
        /// <value>
        /// A <see cref="WebSocketSessionManager"/> that manages the sessions in
        /// the service.
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected WebSocketSessionManager Sessions
        {
            get
            {
                if (_sessions == null)
                {
                    var msg = "The session has not started yet.";

                    throw new InvalidOperationException(msg);
                }

                return _sessions;
            }
        }

        /// <summary>
        /// Gets the client information for a session.
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
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected IPrincipal User
        {
            get
            {
                if (_context == null)
                {
                    var msg = "The session has not started yet.";

                    throw new InvalidOperationException(msg);
                }

                return _context.User;
            }
        }

        /// <summary>
        /// Gets the client endpoint for a session.
        /// </summary>
        /// <value>
        /// A <see cref="System.Net.IPEndPoint"/> that represents the client
        /// IP address and port number.
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected System.Net.IPEndPoint UserEndPoint
        {
            get
            {
                if (_context == null)
                {
                    var msg = "The session has not started yet.";

                    throw new InvalidOperationException(msg);
                }

                return _context.UserEndPoint;
            }
        }

        /// <summary>
        /// Gets or sets the delegate used to validate the HTTP cookies.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="T:System.Func{CookieCollection, CookieCollection, bool}"/>
        ///   delegate.
        ///   </para>
        ///   <para>
        ///   It represents the delegate called when the WebSocket interface
        ///   for a session validates the handshake request.
        ///   </para>
        ///   <para>
        ///   1st <see cref="CookieCollection"/> parameter passed to the delegate
        ///   contains the cookies to validate.
        ///   </para>
        ///   <para>
        ///   2nd <see cref="CookieCollection"/> parameter passed to the delegate
        ///   receives the cookies to send to the client.
        ///   </para>
        ///   <para>
        ///   The method invoked by the delegate must return <c>true</c>
        ///   if the cookies are valid.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        public Func<CookieCollection, CookieCollection, bool> CookiesValidator
        {
            get
            {
                return _cookiesValidator;
            }

            set
            {
                _cookiesValidator = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the message event is emitted
        /// when the WebSocket interface for a session receives a ping.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the interface emits the message event when receives
        ///   a ping; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool EmitOnPing
        {
            get
            {
                return _websocket != null ? _websocket.EmitOnPing : _emitOnPing;
            }

            set
            {
                if (_websocket != null)
                {
                    _websocket.EmitOnPing = value;

                    return;
                }

                _emitOnPing = value;
            }
        }

        /// <summary>
        /// Gets or sets the delegate used to validate the Host header.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="T:System.Func{string, bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It represents the delegate called when the WebSocket interface
        ///   for a session validates the handshake request.
        ///   </para>
        ///   <para>
        ///   The <see cref="string"/> parameter passed to the delegate is
        ///   the value of the Host header.
        ///   </para>
        ///   <para>
        ///   The method invoked by the delegate must return <c>true</c>
        ///   if the header value is valid.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        public Func<string, bool> HostValidator
        {
            get
            {
                return _hostValidator;
            }

            set
            {
                _hostValidator = value;
            }
        }

        /// <summary>
        /// Gets the unique ID of a session.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the unique ID of the session.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the session has not started yet.
        ///   </para>
        /// </value>
        public string ID
        {
            get
            {
                return _id;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the WebSocket interface for
        /// a session ignores the Sec-WebSocket-Extensions header.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the interface ignores the extensions requested
        ///   from the client; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool IgnoreExtensions
        {
            get
            {
                return _ignoreExtensions;
            }

            set
            {
                _ignoreExtensions = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the underlying TCP socket of
        /// the WebSocket interface for a session disables a delay when send or
        /// receive buffer is not full.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the delay is disabled; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        /// <seealso cref="System.Net.Sockets.Socket.NoDelay"/>
        /// <exception cref="InvalidOperationException">
        /// The set operation is not available when the session has already started.
        /// </exception>
        public bool NoDelay
        {
            get
            {
                return _noDelay;
            }

            set
            {
                if (_websocket != null)
                {
                    var msg = "The set operation is not available.";

                    throw new InvalidOperationException(msg);
                }

                _noDelay = value;
            }
        }

        /// <summary>
        /// Gets or sets the delegate used to validate the Origin header.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="T:System.Func{string, bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It represents the delegate called when the WebSocket interface
        ///   for a session validates the handshake request.
        ///   </para>
        ///   <para>
        ///   The <see cref="string"/> parameter passed to the delegate is
        ///   the value of the Origin header or <see langword="null"/> if
        ///   the header is not present.
        ///   </para>
        ///   <para>
        ///   The method invoked by the delegate must return <c>true</c>
        ///   if the header value is valid.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        public Func<string, bool> OriginValidator
        {
            get
            {
                return _originValidator;
            }

            set
            {
                _originValidator = value;
            }
        }

        /// <summary>
        /// Gets or sets the name of the WebSocket subprotocol for a session.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the name of the subprotocol.
        ///   </para>
        ///   <para>
        ///   The value specified for a set operation must be a token defined in
        ///   <see href="http://tools.ietf.org/html/rfc2616#section-2.2">
        ///   RFC 2616</see>.
        ///   </para>
        ///   <para>
        ///   The default value is an empty string.
        ///   </para>
        /// </value>
        /// <exception cref="ArgumentException">
        /// The value specified for a set operation is not a token.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The set operation is not available if the session has already started.
        /// </exception>
        public string Protocol
        {
            get
            {
                return _websocket != null
                       ? _websocket.Protocol
                       : (_protocol ?? String.Empty);
            }

            set
            {
                if (_websocket != null)
                {
                    var msg = "The session has already started.";

                    throw new InvalidOperationException(msg);
                }

                if (value == null || value.Length == 0)
                {
                    _protocol = null;

                    return;
                }

                if (!value.IsToken())
                {
                    var msg = "Not a token.";

                    throw new ArgumentException(msg, "value");
                }

                _protocol = value;
            }
        }

        /// <summary>
        /// Gets the time that a session has started.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="DateTime"/> that represents the time that the session
        ///   has started.
        ///   </para>
        ///   <para>
        ///   <see cref="DateTime.MaxValue"/> if the session has not started yet.
        ///   </para>
        /// </value>
        public DateTime StartTime
        {
            get
            {
                return _startTime;
            }
        }

        private string checkHandshakeRequest(WebSocketContext context)
        {
            if (_hostValidator != null)
            {
                if (!_hostValidator(context.Host))
                {
                    var msg = "The Host header is invalid.";

                    return msg;
                }
            }

            if (_originValidator != null)
            {
                if (!_originValidator(context.Origin))
                {
                    var msg = "The Origin header is non-existent or invalid.";

                    return msg;
                }
            }

            if (_cookiesValidator != null)
            {
                var req = context.CookieCollection;
                var res = context.WebSocket.CookieCollection;

                if (!_cookiesValidator(req, res))
                {
                    var msg = "The Cookie header is non-existent or invalid.";

                    return msg;
                }
            }

            return null;
        }

        private void onClose(object sender, CloseEventArgs e)
        {
            if (_id == null)
                return;

            _sessions.Remove(_id);

            OnClose(e);
        }

        private void onError(object sender, ErrorEventArgs e)
        {
            OnError(e);
        }

        private void onMessage(object sender, MessageEventArgs e)
        {
            OnMessage(e);
        }

        private void onOpen(object sender, EventArgs e)
        {
            _id = _sessions.Add(this);

            if (_id == null)
            {
                _websocket.Close(CloseStatusCode.Away);

                return;
            }

            _startTime = DateTime.Now;

            OnOpen();
        }

        internal void Start(
          WebSocketContext context,
          WebSocketSessionManager sessions
        )
        {
            _context = context;
            _sessions = sessions;

            _websocket = context.WebSocket;
            _websocket.CustomHandshakeRequestChecker = checkHandshakeRequest;
            _websocket.EmitOnPing = _emitOnPing;
            _websocket.IgnoreExtensions = _ignoreExtensions;

            if (_noDelay)
                _websocket.NoDelay = true;

            _websocket.Protocol = _protocol;

            var waitTime = sessions.WaitTime;

            if (waitTime != _websocket.WaitTime)
                _websocket.WaitTime = waitTime;

            _websocket.OnOpen += onOpen;
            _websocket.OnMessage += onMessage;
            _websocket.OnError += onError;
            _websocket.OnClose += onClose;

            _websocket.Accept();
        }

        /// <summary>
        /// Closes the WebSocket connection for a session.
        /// </summary>
        /// <remarks>
        /// This method does nothing if the current state of the WebSocket
        /// interface is Closing or Closed.
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected void Close()
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.Close();
        }

        /// <summary>
        /// Closes the WebSocket connection for a session with the specified
        /// status code and reason.
        /// </summary>
        /// <remarks>
        /// This method does nothing if the current state of the WebSocket
        /// interface is Closing or Closed.
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   A <see cref="ushort"/> that specifies the status code indicating
        ///   the reason for the close.
        ///   </para>
        ///   <para>
        ///   The status codes are defined in
        ///   <see href="http://tools.ietf.org/html/rfc6455#section-7.4">
        ///   Section 7.4</see> of RFC 6455.
        ///   </para>
        /// </param>
        /// <param name="reason">
        ///   <para>
        ///   A <see cref="string"/> that specifies the reason for the close.
        ///   </para>
        ///   <para>
        ///   Its size must be 123 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is 1010 (mandatory extension).
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is 1005 (no status) and
        ///   <paramref name="reason"/> is specified.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="reason"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <para>
        ///   <paramref name="code"/> is less than 1000 or greater than 4999.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The size of <paramref name="reason"/> is greater than 123 bytes.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected void Close(ushort code, string reason)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.Close(code, reason);
        }

        /// <summary>
        /// Closes the WebSocket connection for a session with the specified
        /// status code and reason.
        /// </summary>
        /// <remarks>
        /// This method does nothing if the current state of the WebSocket
        /// interface is Closing or Closed.
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   One of the <see cref="CloseStatusCode"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the status code indicating the reason for the close.
        ///   </para>
        /// </param>
        /// <param name="reason">
        ///   <para>
        ///   A <see cref="string"/> that specifies the reason for the close.
        ///   </para>
        ///   <para>
        ///   Its size must be 123 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is an undefined enum value.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.MandatoryExtension"/>.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.NoStatus"/> and
        ///   <paramref name="reason"/> is specified.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="reason"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The size of <paramref name="reason"/> is greater than 123 bytes.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected void Close(CloseStatusCode code, string reason)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.Close(code, reason);
        }

        /// <summary>
        /// Closes the WebSocket connection for a session asynchronously.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This method does not wait for the close to be complete.
        ///   </para>
        ///   <para>
        ///   This method does nothing if the current state of the WebSocket
        ///   interface is Closing or Closed.
        ///   </para>
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected void CloseAsync()
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.CloseAsync();
        }

        /// <summary>
        /// Closes the WebSocket connection for a session asynchronously with
        /// the specified status code and reason.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This method does not wait for the close to be complete.
        ///   </para>
        ///   <para>
        ///   This method does nothing if the current state of the WebSocket
        ///   interface is Closing or Closed.
        ///   </para>
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   A <see cref="ushort"/> that specifies the status code indicating
        ///   the reason for the close.
        ///   </para>
        ///   <para>
        ///   The status codes are defined in
        ///   <see href="http://tools.ietf.org/html/rfc6455#section-7.4">
        ///   Section 7.4</see> of RFC 6455.
        ///   </para>
        /// </param>
        /// <param name="reason">
        ///   <para>
        ///   A <see cref="string"/> that specifies the reason for the close.
        ///   </para>
        ///   <para>
        ///   Its size must be 123 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is 1010 (mandatory extension).
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is 1005 (no status) and
        ///   <paramref name="reason"/> is specified.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="reason"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <para>
        ///   <paramref name="code"/> is less than 1000 or greater than 4999.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The size of <paramref name="reason"/> is greater than 123 bytes.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected void CloseAsync(ushort code, string reason)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.CloseAsync(code, reason);
        }

        /// <summary>
        /// Closes the WebSocket connection for a session asynchronously with
        /// the specified status code and reason.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This method does not wait for the close to be complete.
        ///   </para>
        ///   <para>
        ///   This method does nothing if the current state of the WebSocket
        ///   interface is Closing or Closed.
        ///   </para>
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   One of the <see cref="CloseStatusCode"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the status code indicating the reason for the close.
        ///   </para>
        /// </param>
        /// <param name="reason">
        ///   <para>
        ///   A <see cref="string"/> that specifies the reason for the close.
        ///   </para>
        ///   <para>
        ///   Its size must be 123 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is an undefined enum value.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.MandatoryExtension"/>.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.NoStatus"/> and
        ///   <paramref name="reason"/> is specified.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="reason"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The size of <paramref name="reason"/> is greater than 123 bytes.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected void CloseAsync(CloseStatusCode code, string reason)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.CloseAsync(code, reason);
        }

        /// <summary>
        /// Called when the WebSocket connection for a session has been closed.
        /// </summary>
        /// <param name="e">
        /// A <see cref="CloseEventArgs"/> that represents the event data passed
        /// from a <see cref="WebSocket.OnClose"/> event.
        /// </param>
        protected virtual void OnClose(CloseEventArgs e)
        {
        }

        /// <summary>
        /// Called when the WebSocket interface for a session gets an error.
        /// </summary>
        /// <param name="e">
        /// A <see cref="ErrorEventArgs"/> that represents the event data passed
        /// from a <see cref="WebSocket.OnError"/> event.
        /// </param>
        protected virtual void OnError(ErrorEventArgs e)
        {
        }

        /// <summary>
        /// Called when the WebSocket interface for a session receives a message.
        /// </summary>
        /// <param name="e">
        /// A <see cref="MessageEventArgs"/> that represents the event data passed
        /// from a <see cref="WebSocket.OnMessage"/> event.
        /// </param>
        protected virtual void OnMessage(MessageEventArgs e)
        {
        }

        /// <summary>
        /// Called when the WebSocket connection for a session has been established.
        /// </summary>
        protected virtual void OnOpen()
        {
        }

        /// <summary>
        /// Sends a ping to the client for a session.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the send has successfully done and a pong has been
        /// received within a time; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected bool Ping()
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            return _websocket.Ping();
        }

        /// <summary>
        /// Sends a ping with the specified message to the client for a session.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the send has successfully done and a pong has been
        /// received within a time; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="message">
        ///   <para>
        ///   A <see cref="string"/> that specifies the message to send.
        ///   </para>
        ///   <para>
        ///   Its size must be 125 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="message"/> could not be UTF-8-encoded.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The size of <paramref name="message"/> is greater than 125 bytes.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The session has not started yet.
        /// </exception>
        protected bool Ping(string message)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            return _websocket.Ping(message);
        }

        /// <summary>
        /// Sends the specified data to the client for a session.
        /// </summary>
        /// <param name="data">
        /// An array of <see cref="byte"/> that specifies the binary data to send.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session has not started yet.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        protected void Send(byte[] data)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.Send(data);
        }

        /// <summary>
        /// Sends the specified file to the client for a session.
        /// </summary>
        /// <param name="fileInfo">
        ///   <para>
        ///   A <see cref="FileInfo"/> that specifies the file to send.
        ///   </para>
        ///   <para>
        ///   The file is sent as the binary data.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   The file does not exist.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The file could not be opened.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileInfo"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session has not started yet.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        protected void Send(FileInfo fileInfo)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.Send(fileInfo);
        }

        /// <summary>
        /// Sends the specified data to the client for a session.
        /// </summary>
        /// <param name="data">
        /// A <see cref="string"/> that specifies the text data to send.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="data"/> could not be UTF-8-encoded.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session has not started yet.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        protected void Send(string data)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.Send(data);
        }

        /// <summary>
        /// Sends the data from the specified stream instance to the client for
        /// a session.
        /// </summary>
        /// <param name="stream">
        ///   <para>
        ///   A <see cref="Stream"/> instance from which to read the data to send.
        ///   </para>
        ///   <para>
        ///   The data is sent as the binary data.
        ///   </para>
        /// </param>
        /// <param name="length">
        /// An <see cref="int"/> that specifies the number of bytes to send.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="stream"/> cannot be read.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is less than 1.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   No data could be read from <paramref name="stream"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="stream"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session has not started yet.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        protected void Send(Stream stream, int length)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.Send(stream, length);
        }

        /// <summary>
        /// Sends the specified data to the client for a session asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="data">
        /// An array of <see cref="byte"/> that specifies the binary data to send.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="T:System.Action{bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the send is complete.
        ///   </para>
        ///   <para>
        ///   The <see cref="bool"/> parameter passed to the delegate is <c>true</c>
        ///   if the send has successfully done; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session has not started yet.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        protected void SendAsync(byte[] data, Action<bool> completed)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.SendAsync(data, completed);
        }

        /// <summary>
        /// Sends the specified file to the client for a session asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="fileInfo">
        ///   <para>
        ///   A <see cref="FileInfo"/> that specifies the file to send.
        ///   </para>
        ///   <para>
        ///   The file is sent as the binary data.
        ///   </para>
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="T:System.Action{bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the send is complete.
        ///   </para>
        ///   <para>
        ///   The <see cref="bool"/> parameter passed to the delegate is <c>true</c>
        ///   if the send has successfully done; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   The file does not exist.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The file could not be opened.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileInfo"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session has not started yet.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        protected void SendAsync(FileInfo fileInfo, Action<bool> completed)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.SendAsync(fileInfo, completed);
        }

        /// <summary>
        /// Sends the specified data to the client for a session asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="data">
        /// A <see cref="string"/> that specifies the text data to send.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="T:System.Action{bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the send is complete.
        ///   </para>
        ///   <para>
        ///   The <see cref="bool"/> parameter passed to the delegate is <c>true</c>
        ///   if the send has successfully done; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="data"/> could not be UTF-8-encoded.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session has not started yet.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        protected void SendAsync(string data, Action<bool> completed)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.SendAsync(data, completed);
        }

        /// <summary>
        /// Sends the data from the specified stream instance to the client for
        /// a session asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="stream">
        ///   <para>
        ///   A <see cref="Stream"/> instance from which to read the data to send.
        ///   </para>
        ///   <para>
        ///   The data is sent as the binary data.
        ///   </para>
        /// </param>
        /// <param name="length">
        /// An <see cref="int"/> that specifies the number of bytes to send.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="T:System.Action{bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the send is complete.
        ///   </para>
        ///   <para>
        ///   The <see cref="bool"/> parameter passed to the delegate is <c>true</c>
        ///   if the send has successfully done; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="stream"/> cannot be read.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is less than 1.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   No data could be read from <paramref name="stream"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="stream"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session has not started yet.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        protected void SendAsync(Stream stream, int length, Action<bool> completed)
        {
            if (_websocket == null)
            {
                var msg = "The session has not started yet.";

                throw new InvalidOperationException(msg);
            }

            _websocket.SendAsync(stream, length, completed);
        }

        /// <summary>
        /// Gets the WebSocket interface for a session.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="WebSocketSharp.WebSocket"/> that represents
        ///   the WebSocket interface.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the session has not started yet.
        ///   </para>
        /// </value>
        WebSocket IWebSocketSession.WebSocket
        {
            get
            {
                return _websocket;
            }
        }
    }
    //=============================================================================
    /// <summary>
    /// Provides a WebSocket protocol server.
    /// </summary>
    /// <remarks>
    /// This class can provide multiple WebSocket services.
    /// </remarks>
    public class WebSocketServer
    {
        private System.Net.IPAddress _address;
        private AuthenticationSchemes _authSchemes;
        private static readonly string _defaultRealm;
        private string _hostname;
        private bool _isDnsStyle;
        private bool _isSecure;
        private TcpListener _listener;
        private Logger _log;
        private int _port;
        private string _realm;
        private string _realmInUse;
        private Thread _receiveThread;
        private bool _reuseAddress;
        private WebSocketServiceManager _services;
        private ServerSslConfiguration _sslConfig;
        private ServerSslConfiguration _sslConfigInUse;
        private volatile ServerState _state;
        private object _sync;
        private Func<IIdentity, NetworkCredential> _userCredFinder;

        static WebSocketServer()
        {
            _defaultRealm = "SECRET AREA";
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WebSocketServer"/> class.
        /// </summary>
        /// <remarks>
        /// The new instance listens for incoming handshake requests on
        /// <see cref="System.Net.IPAddress.Any"/> and port 80.
        /// </remarks>
        public WebSocketServer()
        {
            var addr = System.Net.IPAddress.Any;

            init(addr.ToString(), addr, 80, false);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WebSocketServer"/> class
        /// with the specified port.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   The new instance listens for incoming handshake requests on
        ///   <see cref="System.Net.IPAddress.Any"/> and <paramref name="port"/>.
        ///   </para>
        ///   <para>
        ///   It provides secure connections if <paramref name="port"/> is 443.
        ///   </para>
        /// </remarks>
        /// <param name="port">
        /// An <see cref="int"/> that specifies the number of the port on which
        /// to listen.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="port"/> is less than 1 or greater than 65535.
        /// </exception>
        public WebSocketServer(int port)
          : this(port, port == 443)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WebSocketServer"/> class
        /// with the specified URL.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   The new instance listens for incoming handshake requests on
        ///   the IP address and port of <paramref name="url"/>.
        ///   </para>
        ///   <para>
        ///   Either port 80 or 443 is used if <paramref name="url"/> includes
        ///   no port. Port 443 is used if the scheme of <paramref name="url"/>
        ///   is wss; otherwise, port 80 is used.
        ///   </para>
        ///   <para>
        ///   The new instance provides secure connections if the scheme of
        ///   <paramref name="url"/> is wss.
        ///   </para>
        /// </remarks>
        /// <param name="url">
        /// A <see cref="string"/> that specifies the WebSocket URL of the server.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="url"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="url"/> is invalid.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="url"/> is <see langword="null"/>.
        /// </exception>
        public WebSocketServer(string url)
        {
            if (url == null)
                throw new ArgumentNullException("url");

            if (url.Length == 0)
                throw new ArgumentException("An empty string.", "url");

            Uri uri;
            string msg;

            if (!tryCreateUri(url, out uri, out msg))
                throw new ArgumentException(msg, "url");

            var host = uri.DnsSafeHost;
            var addr = host.ToIPAddress();

            if (addr == null)
            {
                msg = "The host part could not be converted to an IP address.";

                throw new ArgumentException(msg, "url");
            }

            if (!addr.IsLocal())
            {
                msg = "The IP address of the host is not a local IP address.";

                throw new ArgumentException(msg, "url");
            }

            init(host, addr, uri.Port, uri.Scheme == "wss");
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WebSocketServer"/> class
        /// with the specified port and boolean if secure or not.
        /// </summary>
        /// <remarks>
        /// The new instance listens for incoming handshake requests on
        /// <see cref="System.Net.IPAddress.Any"/> and <paramref name="port"/>.
        /// </remarks>
        /// <param name="port">
        /// An <see cref="int"/> that specifies the number of the port on which
        /// to listen.
        /// </param>
        /// <param name="secure">
        /// A <see cref="bool"/>: <c>true</c> if the new instance provides
        /// secure connections; otherwise, <c>false</c>.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="port"/> is less than 1 or greater than 65535.
        /// </exception>
        public WebSocketServer(int port, bool secure)
        {
            if (!port.IsPortNumber())
            {
                var msg = "Less than 1 or greater than 65535.";

                throw new ArgumentOutOfRangeException("port", msg);
            }

            var addr = System.Net.IPAddress.Any;

            init(addr.ToString(), addr, port, secure);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WebSocketServer"/> class
        /// with the specified IP address and port.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   The new instance listens for incoming handshake requests on
        ///   <paramref name="address"/> and <paramref name="port"/>.
        ///   </para>
        ///   <para>
        ///   It provides secure connections if <paramref name="port"/> is 443.
        ///   </para>
        /// </remarks>
        /// <param name="address">
        /// A <see cref="System.Net.IPAddress"/> that specifies the local IP
        /// address on which to listen.
        /// </param>
        /// <param name="port">
        /// An <see cref="int"/> that specifies the number of the port on which
        /// to listen.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="address"/> is not a local IP address.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="address"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="port"/> is less than 1 or greater than 65535.
        /// </exception>
        public WebSocketServer(System.Net.IPAddress address, int port)
          : this(address, port, port == 443)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WebSocketServer"/> class
        /// with the specified IP address, port, and boolean if secure or not.
        /// </summary>
        /// <remarks>
        /// The new instance listens for incoming handshake requests on
        /// <paramref name="address"/> and <paramref name="port"/>.
        /// </remarks>
        /// <param name="address">
        /// A <see cref="System.Net.IPAddress"/> that specifies the local IP
        /// address on which to listen.
        /// </param>
        /// <param name="port">
        /// An <see cref="int"/> that specifies the number of the port on which
        /// to listen.
        /// </param>
        /// <param name="secure">
        /// A <see cref="bool"/>: <c>true</c> if the new instance provides
        /// secure connections; otherwise, <c>false</c>.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="address"/> is not a local IP address.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="address"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="port"/> is less than 1 or greater than 65535.
        /// </exception>
        public WebSocketServer(System.Net.IPAddress address, int port, bool secure)
        {
            if (address == null)
                throw new ArgumentNullException("address");

            if (!address.IsLocal())
            {
                var msg = "Not a local IP address.";

                throw new ArgumentException(msg, "address");
            }

            if (!port.IsPortNumber())
            {
                var msg = "Less than 1 or greater than 65535.";

                throw new ArgumentOutOfRangeException("port", msg);
            }

            init(address.ToString(), address, port, secure);
        }

        /// <summary>
        /// Gets the IP address of the server.
        /// </summary>
        /// <value>
        /// A <see cref="System.Net.IPAddress"/> that represents the local IP
        /// address on which to listen for incoming handshake requests.
        /// </value>
        public System.Net.IPAddress Address
        {
            get
            {
                return _address;
            }
        }

        /// <summary>
        /// Gets or sets the scheme used to authenticate the clients.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
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
        public AuthenticationSchemes AuthenticationSchemes
        {
            get
            {
                return _authSchemes;
            }

            set
            {
                lock (_sync)
                {
                    if (!canSet())
                        return;

                    _authSchemes = value;
                }
            }
        }

        /// <summary>
        /// Gets a value indicating whether the server has started.
        /// </summary>
        /// <value>
        /// <c>true</c> if the server has started; otherwise, <c>false</c>.
        /// </value>
        public bool IsListening
        {
            get
            {
                return _state == ServerState.Start;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the server provides secure connections.
        /// </summary>
        /// <value>
        /// <c>true</c> if the server provides secure connections; otherwise,
        /// <c>false</c>.
        /// </value>
        public bool IsSecure
        {
            get
            {
                return _isSecure;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the server cleans up
        /// the inactive sessions periodically.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the server cleans up the inactive sessions
        ///   every 60 seconds; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool KeepClean
        {
            get
            {
                return _services.KeepClean;
            }

            set
            {
                _services.KeepClean = value;
            }
        }

        /// <summary>
        /// Gets the logging function for the server.
        /// </summary>
        /// <remarks>
        /// The default logging level is <see cref="LogLevel.Error"/>.
        /// </remarks>
        /// <value>
        /// A <see cref="Logger"/> that provides the logging function.
        /// </value>
        public Logger Log
        {
            get
            {
                return _log;
            }
        }

        /// <summary>
        /// Gets the port of the server.
        /// </summary>
        /// <value>
        /// An <see cref="int"/> that represents the number of the port on which
        /// to listen for incoming handshake requests.
        /// </value>
        public int Port
        {
            get
            {
                return _port;
            }
        }

        /// <summary>
        /// Gets or sets the name of the realm associated with the server.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the name of the realm.
        ///   </para>
        ///   <para>
        ///   "SECRET AREA" is used as the name of the realm if the value is
        ///   <see langword="null"/> or an empty string.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        public string Realm
        {
            get
            {
                return _realm;
            }

            set
            {
                lock (_sync)
                {
                    if (!canSet())
                        return;

                    _realm = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the server is allowed to
        /// be bound to an address that is already in use.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   You should set this property to <c>true</c> if you would like to
        ///   resolve to wait for socket in TIME_WAIT state.
        ///   </para>
        ///   <para>
        ///   The set operation works if the current state of the server is
        ///   Ready or Stop.
        ///   </para>
        /// </remarks>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the server is allowed to be bound to an address
        ///   that is already in use; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool ReuseAddress
        {
            get
            {
                return _reuseAddress;
            }

            set
            {
                lock (_sync)
                {
                    if (!canSet())
                        return;

                    _reuseAddress = value;
                }
            }
        }

        /// <summary>
        /// Gets the configuration for secure connection.
        /// </summary>
        /// <remarks>
        /// The configuration is used when the server attempts to start,
        /// so it must be configured before the start method is called.
        /// </remarks>
        /// <value>
        /// A <see cref="ServerSslConfiguration"/> that represents the
        /// configuration used to provide secure connections.
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The server does not provide secure connections.
        /// </exception>
        public ServerSslConfiguration SslConfiguration
        {
            get
            {
                if (!_isSecure)
                {
                    var msg = "The server does not provide secure connections.";

                    throw new InvalidOperationException(msg);
                }

                return getSslConfiguration();
            }
        }

        /// <summary>
        /// Gets or sets the delegate called to find the credentials for
        /// an identity used to authenticate a client.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="T:System.Func{IIdentity, NetworkCredential}"/>
        ///   delegate.
        ///   </para>
        ///   <para>
        ///   It represents the delegate called when the server finds
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
        public Func<IIdentity, NetworkCredential> UserCredentialsFinder
        {
            get
            {
                return _userCredFinder;
            }

            set
            {
                lock (_sync)
                {
                    if (!canSet())
                        return;

                    _userCredFinder = value;
                }
            }
        }

        /// <summary>
        /// Gets or sets the time to wait for the response to the WebSocket
        /// Ping or Close.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="TimeSpan"/> that represents the time to wait for
        ///   the response.
        ///   </para>
        ///   <para>
        ///   The default value is the same as 1 second.
        ///   </para>
        /// </value>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The value specified for a set operation is zero or less.
        /// </exception>
        public TimeSpan WaitTime
        {
            get
            {
                return _services.WaitTime;
            }

            set
            {
                _services.WaitTime = value;
            }
        }

        /// <summary>
        /// Gets the management function for the WebSocket services provided by
        /// the server.
        /// </summary>
        /// <value>
        /// A <see cref="WebSocketServiceManager"/> that manages the WebSocket
        /// services provided by the server.
        /// </value>
        public WebSocketServiceManager WebSocketServices
        {
            get
            {
                return _services;
            }
        }

        private void abort()
        {
            lock (_sync)
            {
                if (_state != ServerState.Start)
                    return;

                _state = ServerState.ShuttingDown;
            }

            try
            {
                _listener.Stop();
            }
            catch (Exception ex)
            {
                _log.Fatal(ex.Message);
                _log.Debug(ex.ToString());
            }

            try
            {
                _services.Stop(1006, String.Empty);
            }
            catch (Exception ex)
            {
                _log.Fatal(ex.Message);
                _log.Debug(ex.ToString());
            }

            _state = ServerState.Stop;
        }

        private bool authenticateClient(TcpListenerWebSocketContext context)
        {
            if (_authSchemes == AuthenticationSchemes.Anonymous)
                return true;

            if (_authSchemes == AuthenticationSchemes.None)
                return false;

            var chal = new AuthenticationChallenge(_authSchemes, _realmInUse)
                       .ToString();

            var retry = -1;
            Func<bool> auth = null;
            auth =
              () => {
                  retry++;

                  if (retry > 99)
                      return false;

                  if (context.SetUser(_authSchemes, _realmInUse, _userCredFinder))
                      return true;

                  context.SendAuthenticationChallenge(chal);

                  return auth();
              };

            return auth();
        }

        private bool canSet()
        {
            return _state == ServerState.Ready || _state == ServerState.Stop;
        }

        private bool checkHostNameForRequest(string name)
        {
            return !_isDnsStyle
                   || Uri.CheckHostName(name) != UriHostNameType.Dns
                   || name == _hostname;
        }

        private string getRealm()
        {
            var realm = _realm;

            return realm != null && realm.Length > 0 ? realm : _defaultRealm;
        }

        private ServerSslConfiguration getSslConfiguration()
        {
            if (_sslConfig == null)
                _sslConfig = new ServerSslConfiguration();

            return _sslConfig;
        }

        private void init(
          string hostname,
          System.Net.IPAddress address,
          int port,
          bool secure
        )
        {
            _hostname = hostname;
            _address = address;
            _port = port;
            _isSecure = secure;

            _authSchemes = AuthenticationSchemes.Anonymous;
            _isDnsStyle = Uri.CheckHostName(hostname) == UriHostNameType.Dns;
            _listener = new TcpListener(address, port);
            _log = new Logger();
            _services = new WebSocketServiceManager(_log);
            _sync = new object();
        }

        private void processRequest(TcpListenerWebSocketContext context)
        {
            if (!authenticateClient(context))
            {
                context.Close(HttpStatusCode.Forbidden);

                return;
            }

            var uri = context.RequestUri;

            if (uri == null)
            {
                context.Close(HttpStatusCode.BadRequest);

                return;
            }

            var name = uri.DnsSafeHost;

            if (!checkHostNameForRequest(name))
            {
                context.Close(HttpStatusCode.NotFound);

                return;
            }

            var path = uri.AbsolutePath;

            if (path.IndexOfAny(new[] { '%', '+' }) > -1)
                path = HttpUtility.UrlDecode(path, Encoding.UTF8);

            WebSocketServiceHost host;

            if (!_services.InternalTryGetServiceHost(path, out host))
            {
                context.Close(HttpStatusCode.NotImplemented);

                return;
            }

            host.StartSession(context);
        }

        private void receiveRequest()
        {
            while (true)
            {
                TcpClient cl = null;

                try
                {
                    cl = _listener.AcceptTcpClient();

                    ThreadPool.QueueUserWorkItem(
                      state => {
                          try
                          {
                              var ctx = new TcpListenerWebSocketContext(
                                cl,
                                null,
                                _isSecure,
                                _sslConfigInUse,
                                _log
                              );

                              processRequest(ctx);
                          }
                          catch (Exception ex)
                          {
                              _log.Error(ex.Message);
                              _log.Debug(ex.ToString());

                              cl.Close();
                          }
                      }
                    );
                }
                catch (SocketException ex)
                {
                    if (_state == ServerState.ShuttingDown)
                        return;

                    _log.Fatal(ex.Message);
                    _log.Debug(ex.ToString());

                    break;
                }
                catch (InvalidOperationException ex)
                {
                    if (_state == ServerState.ShuttingDown)
                        return;

                    _log.Fatal(ex.Message);
                    _log.Debug(ex.ToString());

                    break;
                }
                catch (Exception ex)
                {
                    _log.Fatal(ex.Message);
                    _log.Debug(ex.ToString());

                    if (cl != null)
                        cl.Close();

                    if (_state == ServerState.ShuttingDown)
                        return;

                    break;
                }
            }

            abort();
        }

        private void start()
        {
            lock (_sync)
            {
                if (_state == ServerState.Start || _state == ServerState.ShuttingDown)
                    return;

                if (_isSecure)
                {
                    var src = getSslConfiguration();
                    var conf = new ServerSslConfiguration(src);

                    if (conf.ServerCertificate == null)
                    {
                        var msg = "There is no server certificate for secure connection.";

                        throw new InvalidOperationException(msg);
                    }

                    _sslConfigInUse = conf;
                }

                _realmInUse = getRealm();

                _services.Start();

                try
                {
                    startReceiving();
                }
                catch
                {
                    _services.Stop(1011, String.Empty);

                    throw;
                }

                _state = ServerState.Start;
            }
        }

        private void startReceiving()
        {
            if (_reuseAddress)
            {
                _listener.Server.SetSocketOption(
                  SocketOptionLevel.Socket,
                  SocketOptionName.ReuseAddress,
                  true
                );
            }

            try
            {
                _listener.Start();
            }
            catch (Exception ex)
            {
                var msg = "The underlying listener has failed to start.";

                throw new InvalidOperationException(msg, ex);
            }

            var receiver = new ThreadStart(receiveRequest);
            _receiveThread = new Thread(receiver);
            _receiveThread.IsBackground = true;

            _receiveThread.Start();
        }

        private void stop(ushort code, string reason)
        {
            lock (_sync)
            {
                if (_state != ServerState.Start)
                    return;

                _state = ServerState.ShuttingDown;
            }

            try
            {
                var timeout = 5000;

                stopReceiving(timeout);
            }
            catch (Exception ex)
            {
                _log.Fatal(ex.Message);
                _log.Debug(ex.ToString());
            }

            try
            {
                _services.Stop(code, reason);
            }
            catch (Exception ex)
            {
                _log.Fatal(ex.Message);
                _log.Debug(ex.ToString());
            }

            _state = ServerState.Stop;
        }

        private void stopReceiving(int millisecondsTimeout)
        {
            _listener.Stop();
            _receiveThread.Join(millisecondsTimeout);
        }

        private static bool tryCreateUri(
          string uriString,
          out Uri result,
          out string message
        )
        {
            if (!uriString.TryCreateWebSocketUri(out result, out message))
                return false;

            if (result.PathAndQuery != "/")
            {
                result = null;
                message = "It includes either or both path and query components.";

                return false;
            }

            return true;
        }

        /// <summary>
        /// Adds a WebSocket service with the specified behavior and path.
        /// </summary>
        /// <param name="path">
        ///   <para>
        ///   A <see cref="string"/> that specifies an absolute path to
        ///   the service to add.
        ///   </para>
        ///   <para>
        ///   / is trimmed from the end of the string if present.
        ///   </para>
        /// </param>
        /// <typeparam name="TBehavior">
        ///   <para>
        ///   The type of the behavior for the service.
        ///   </para>
        ///   <para>
        ///   It must inherit the <see cref="WebSocketBehavior"/> class.
        ///   </para>
        ///   <para>
        ///   Also it must have a public parameterless constructor.
        ///   </para>
        /// </typeparam>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is not an absolute path.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> includes either or both
        ///   query and fragment components.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is already in use.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public void AddWebSocketService<TBehavior>(string path)
          where TBehavior : WebSocketBehavior, new()
        {
            _services.AddService<TBehavior>(path, null);
        }

        /// <summary>
        /// Adds a WebSocket service with the specified behavior, path,
        /// and initializer.
        /// </summary>
        /// <param name="path">
        ///   <para>
        ///   A <see cref="string"/> that specifies an absolute path to
        ///   the service to add.
        ///   </para>
        ///   <para>
        ///   / is trimmed from the end of the string if present.
        ///   </para>
        /// </param>
        /// <param name="initializer">
        ///   <para>
        ///   An <see cref="T:System.Action{TBehavior}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the service initializes
        ///   a new session instance.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <typeparam name="TBehavior">
        ///   <para>
        ///   The type of the behavior for the service.
        ///   </para>
        ///   <para>
        ///   It must inherit the <see cref="WebSocketBehavior"/> class.
        ///   </para>
        ///   <para>
        ///   Also it must have a public parameterless constructor.
        ///   </para>
        /// </typeparam>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is not an absolute path.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> includes either or both
        ///   query and fragment components.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is already in use.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public void AddWebSocketService<TBehavior>(
          string path,
          Action<TBehavior> initializer
        )
          where TBehavior : WebSocketBehavior, new()
        {
            _services.AddService<TBehavior>(path, initializer);
        }

        /// <summary>
        /// Removes a WebSocket service with the specified path.
        /// </summary>
        /// <remarks>
        /// The service is stopped with close status 1001 (going away)
        /// if the current state of the service is Start.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if the service is successfully found and removed;
        /// otherwise, <c>false</c>.
        /// </returns>
        /// <param name="path">
        ///   <para>
        ///   A <see cref="string"/> that specifies an absolute path to
        ///   the service to remove.
        ///   </para>
        ///   <para>
        ///   / is trimmed from the end of the string if present.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is not an absolute path.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> includes either or both
        ///   query and fragment components.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public bool RemoveWebSocketService(string path)
        {
            return _services.RemoveService(path);
        }

        /// <summary>
        /// Starts receiving incoming handshake requests.
        /// </summary>
        /// <remarks>
        /// This method works if the current state of the server is Ready or Stop.
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   There is no server certificate for secure connection.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The underlying <see cref="TcpListener"/> has failed to start.
        ///   </para>
        /// </exception>
        public void Start()
        {
            if (_state == ServerState.Start || _state == ServerState.ShuttingDown)
                return;

            start();
        }

        /// <summary>
        /// Stops receiving incoming handshake requests.
        /// </summary>
        /// <remarks>
        /// This method works if the current state of the server is Start.
        /// </remarks>
        public void Stop()
        {
            if (_state != ServerState.Start)
                return;

            stop(1001, String.Empty);
        }
    }
    //=========================================================================================
    /// <summary>
    /// Exposes the methods and properties used to access the information in
    /// a WebSocket service provided by the <see cref="WebSocketServer"/> or
    /// <see cref="HttpServer"/> class.
    /// </summary>
    /// <remarks>
    /// This class is an abstract class.
    /// </remarks>
    public abstract class WebSocketServiceHost
    {
        private Logger _log;
        private string _path;
        private WebSocketSessionManager _sessions;

        /// <summary>
        /// Initializes a new instance of the <see cref="WebSocketServiceHost"/>
        /// class with the specified path and logging function.
        /// </summary>
        /// <param name="path">
        /// A <see cref="string"/> that specifies the absolute path to
        /// the service.
        /// </param>
        /// <param name="log">
        /// A <see cref="Logger"/> that specifies the logging function for
        /// the service.
        /// </param>
        protected WebSocketServiceHost(string path, Logger log)
        {
            _path = path;
            _log = log;

            _sessions = new WebSocketSessionManager(log);
        }

        internal ServerState State
        {
            get
            {
                return _sessions.State;
            }
        }

        /// <summary>
        /// Gets the logging function for the service.
        /// </summary>
        /// <value>
        /// A <see cref="Logger"/> that provides the logging function.
        /// </value>
        protected Logger Log
        {
            get
            {
                return _log;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the service cleans up
        /// the inactive sessions periodically.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the service is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        /// <c>true</c> if the service cleans up the inactive sessions every
        /// 60 seconds; otherwise, <c>false</c>.
        /// </value>
        public bool KeepClean
        {
            get
            {
                return _sessions.KeepClean;
            }

            set
            {
                _sessions.KeepClean = value;
            }
        }

        /// <summary>
        /// Gets the path to the service.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the absolute path to
        /// the service.
        /// </value>
        public string Path
        {
            get
            {
                return _path;
            }
        }

        /// <summary>
        /// Gets the management function for the sessions in the service.
        /// </summary>
        /// <value>
        /// A <see cref="WebSocketSessionManager"/> that manages the sessions in
        /// the service.
        /// </value>
        public WebSocketSessionManager Sessions
        {
            get
            {
                return _sessions;
            }
        }

        /// <summary>
        /// Gets the type of the behavior of the service.
        /// </summary>
        /// <value>
        /// A <see cref="Type"/> that represents the type of the behavior of
        /// the service.
        /// </value>
        public abstract Type BehaviorType { get; }

        /// <summary>
        /// Gets or sets the time to wait for the response to the WebSocket
        /// Ping or Close.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the service is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        /// A <see cref="TimeSpan"/> that represents the time to wait for
        /// the response.
        /// </value>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The value specified for a set operation is zero or less.
        /// </exception>
        public TimeSpan WaitTime
        {
            get
            {
                return _sessions.WaitTime;
            }

            set
            {
                _sessions.WaitTime = value;
            }
        }

        internal void Start()
        {
            _sessions.Start();
        }

        internal void StartSession(WebSocketContext context)
        {
            CreateSession().Start(context, _sessions);
        }

        internal void Stop(ushort code, string reason)
        {
            _sessions.Stop(code, reason);
        }

        /// <summary>
        /// Creates a new session for the service.
        /// </summary>
        /// <returns>
        /// A <see cref="WebSocketBehavior"/> instance that represents
        /// the new session.
        /// </returns>
        protected abstract WebSocketBehavior CreateSession();
    }
    //============================================================================
    internal class WebSocketServiceHost<TBehavior> : WebSocketServiceHost
  where TBehavior : WebSocketBehavior, new()
    {
        private Func<TBehavior> _creator;

        internal WebSocketServiceHost(
          string path,
          Action<TBehavior> initializer,
          Logger log
        )
          : base(path, log)
        {
            _creator = createSessionCreator(initializer);
        }

        public override Type BehaviorType
        {
            get
            {
                return typeof(TBehavior);
            }
        }

        private static Func<TBehavior> createSessionCreator(
          Action<TBehavior> initializer
        )
        {
            if (initializer == null)
                return () => new TBehavior();

            return () => {
                var ret = new TBehavior();

                initializer(ret);

                return ret;
            };
        }

        protected override WebSocketBehavior CreateSession()
        {
            return _creator();
        }
    }
    //========================================================================================
    /// <summary>
    /// Provides the management function for the WebSocket services.
    /// </summary>
    /// <remarks>
    /// This class manages the WebSocket services provided by the
    /// <see cref="WebSocketServer"/> or <see cref="HttpServer"/> class.
    /// </remarks>
    public class WebSocketServiceManager
    {
        private Dictionary<string, WebSocketServiceHost> _hosts;
        private volatile bool _keepClean;
        private Logger _log;
        private volatile ServerState _state;
        private object _sync;
        private TimeSpan _waitTime;

        internal WebSocketServiceManager(Logger log)
        {
            _log = log;

            _hosts = new Dictionary<string, WebSocketServiceHost>();
            _state = ServerState.Ready;
            _sync = ((ICollection)_hosts).SyncRoot;
            _waitTime = TimeSpan.FromSeconds(1);
        }

        /// <summary>
        /// Gets the number of the WebSocket services.
        /// </summary>
        /// <value>
        /// An <see cref="int"/> that represents the number of the services.
        /// </value>
        public int Count
        {
            get
            {
                lock (_sync)
                    return _hosts.Count;
            }
        }

        /// <summary>
        /// Gets the service host instances for the WebSocket services.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An <see cref="T:System.Collections.Generic.IEnumerable{WebSocketServiceHost}"/>
        ///   instance.
        ///   </para>
        ///   <para>
        ///   It provides an enumerator which supports the iteration over
        ///   the collection of the service host instances.
        ///   </para>
        /// </value>
        public IEnumerable<WebSocketServiceHost> Hosts
        {
            get
            {
                lock (_sync)
                    return _hosts.Values.ToList();
            }
        }

        /// <summary>
        /// Gets the service host instance for a WebSocket service with
        /// the specified path.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="WebSocketServiceHost"/> instance that represents
        ///   the service host instance.
        ///   </para>
        ///   <para>
        ///   It provides the function to access the information in the service.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not found.
        ///   </para>
        /// </value>
        /// <param name="path">
        ///   <para>
        ///   A <see cref="string"/> that specifies an absolute path to
        ///   the service to get.
        ///   </para>
        ///   <para>
        ///   / is trimmed from the end of the string if present.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is not an absolute path.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> includes either or both
        ///   query and fragment components.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public WebSocketServiceHost this[string path]
        {
            get
            {
                if (path == null)
                    throw new ArgumentNullException("path");

                if (path.Length == 0)
                    throw new ArgumentException("An empty string.", "path");

                if (path[0] != '/')
                {
                    var msg = "Not an absolute path.";

                    throw new ArgumentException(msg, "path");
                }

                if (path.IndexOfAny(new[] { '?', '#' }) > -1)
                {
                    var msg = "It includes either or both query and fragment components.";

                    throw new ArgumentException(msg, "path");
                }

                WebSocketServiceHost host;

                InternalTryGetServiceHost(path, out host);

                return host;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the inactive sessions in
        /// the WebSocket services are cleaned up periodically.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the inactive sessions are cleaned up every 60
        ///   seconds; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool KeepClean
        {
            get
            {
                return _keepClean;
            }

            set
            {
                lock (_sync)
                {
                    if (!canSet())
                        return;

                    foreach (var host in _hosts.Values)
                        host.KeepClean = value;

                    _keepClean = value;
                }
            }
        }

        /// <summary>
        /// Gets the paths for the WebSocket services.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An <see cref="T:System.Collections.Generic.IEnumerable{string}"/>
        ///   instance.
        ///   </para>
        ///   <para>
        ///   It provides an enumerator which supports the iteration over
        ///   the collection of the paths.
        ///   </para>
        /// </value>
        public IEnumerable<string> Paths
        {
            get
            {
                lock (_sync)
                    return _hosts.Keys.ToList();
            }
        }

        /// <summary>
        /// Gets or sets the time to wait for the response to the WebSocket
        /// Ping or Close.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the server is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="TimeSpan"/> that represents the time to wait for
        ///   the response.
        ///   </para>
        ///   <para>
        ///   The default value is the same as 1 second.
        ///   </para>
        /// </value>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The value specified for a set operation is zero or less.
        /// </exception>
        public TimeSpan WaitTime
        {
            get
            {
                return _waitTime;
            }

            set
            {
                if (value <= TimeSpan.Zero)
                {
                    var msg = "Zero or less.";

                    throw new ArgumentOutOfRangeException("value", msg);
                }

                lock (_sync)
                {
                    if (!canSet())
                        return;

                    foreach (var host in _hosts.Values)
                        host.WaitTime = value;

                    _waitTime = value;
                }
            }
        }

        private bool canSet()
        {
            return _state == ServerState.Ready || _state == ServerState.Stop;
        }

        internal bool InternalTryGetServiceHost(
          string path,
          out WebSocketServiceHost host
        )
        {
            path = path.TrimSlashFromEnd();

            lock (_sync)
                return _hosts.TryGetValue(path, out host);
        }

        internal void Start()
        {
            lock (_sync)
            {
                foreach (var host in _hosts.Values)
                    host.Start();

                _state = ServerState.Start;
            }
        }

        internal void Stop(ushort code, string reason)
        {
            lock (_sync)
            {
                _state = ServerState.ShuttingDown;

                foreach (var host in _hosts.Values)
                    host.Stop(code, reason);

                _state = ServerState.Stop;
            }
        }

        /// <summary>
        /// Adds a WebSocket service with the specified behavior, path,
        /// and initializer.
        /// </summary>
        /// <param name="path">
        ///   <para>
        ///   A <see cref="string"/> that specifies an absolute path to
        ///   the service to add.
        ///   </para>
        ///   <para>
        ///   / is trimmed from the end of the string if present.
        ///   </para>
        /// </param>
        /// <param name="initializer">
        ///   <para>
        ///   An <see cref="T:System.Action{TBehavior}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the service initializes
        ///   a new session instance.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <typeparam name="TBehavior">
        ///   <para>
        ///   The type of the behavior for the service.
        ///   </para>
        ///   <para>
        ///   It must inherit the <see cref="WebSocketBehavior"/> class.
        ///   </para>
        ///   <para>
        ///   Also it must have a public parameterless constructor.
        ///   </para>
        /// </typeparam>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is not an absolute path.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> includes either or both
        ///   query and fragment components.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is already in use.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public void AddService<TBehavior>(
          string path,
          Action<TBehavior> initializer
        )
          where TBehavior : WebSocketBehavior, new()
        {
            if (path == null)
                throw new ArgumentNullException("path");

            if (path.Length == 0)
                throw new ArgumentException("An empty string.", "path");

            if (path[0] != '/')
            {
                var msg = "Not an absolute path.";

                throw new ArgumentException(msg, "path");
            }

            if (path.IndexOfAny(new[] { '?', '#' }) > -1)
            {
                var msg = "It includes either or both query and fragment components.";

                throw new ArgumentException(msg, "path");
            }

            path = path.TrimSlashFromEnd();

            lock (_sync)
            {
                WebSocketServiceHost host;

                if (_hosts.TryGetValue(path, out host))
                {
                    var msg = "It is already in use.";

                    throw new ArgumentException(msg, "path");
                }

                host = new WebSocketServiceHost<TBehavior>(path, initializer, _log);

                if (_keepClean)
                    host.KeepClean = true;

                if (_waitTime != host.WaitTime)
                    host.WaitTime = _waitTime;

                if (_state == ServerState.Start)
                    host.Start();

                _hosts.Add(path, host);
            }
        }

        /// <summary>
        /// Removes all WebSocket services managed by the manager.
        /// </summary>
        /// <remarks>
        /// Each service is stopped with close status 1001 (going away)
        /// if the current state of the service is Start.
        /// </remarks>
        public void Clear()
        {
            List<WebSocketServiceHost> hosts = null;

            lock (_sync)
            {
                hosts = _hosts.Values.ToList();

                _hosts.Clear();
            }

            foreach (var host in hosts)
            {
                if (host.State == ServerState.Start)
                    host.Stop(1001, String.Empty);
            }
        }

        /// <summary>
        /// Removes a WebSocket service with the specified path.
        /// </summary>
        /// <remarks>
        /// The service is stopped with close status 1001 (going away)
        /// if the current state of the service is Start.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if the service is successfully found and removed;
        /// otherwise, <c>false</c>.
        /// </returns>
        /// <param name="path">
        ///   <para>
        ///   A <see cref="string"/> that specifies an absolute path to
        ///   the service to remove.
        ///   </para>
        ///   <para>
        ///   / is trimmed from the end of the string if present.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is not an absolute path.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> includes either or both
        ///   query and fragment components.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public bool RemoveService(string path)
        {
            if (path == null)
                throw new ArgumentNullException("path");

            if (path.Length == 0)
                throw new ArgumentException("An empty string.", "path");

            if (path[0] != '/')
            {
                var msg = "Not an absolute path.";

                throw new ArgumentException(msg, "path");
            }

            if (path.IndexOfAny(new[] { '?', '#' }) > -1)
            {
                var msg = "It includes either or both query and fragment components.";

                throw new ArgumentException(msg, "path");
            }

            path = path.TrimSlashFromEnd();
            WebSocketServiceHost host;

            lock (_sync)
            {
                if (!_hosts.TryGetValue(path, out host))
                    return false;

                _hosts.Remove(path);
            }

            if (host.State == ServerState.Start)
                host.Stop(1001, String.Empty);

            return true;
        }

        /// <summary>
        /// Tries to get the service host instance for a WebSocket service with
        /// the specified path.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the try has succeeded; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="path">
        ///   <para>
        ///   A <see cref="string"/> that specifies an absolute path to
        ///   the service to get.
        ///   </para>
        ///   <para>
        ///   / is trimmed from the end of the string if present.
        ///   </para>
        /// </param>
        /// <param name="host">
        ///   <para>
        ///   When this method returns, a <see cref="WebSocketServiceHost"/>
        ///   instance that receives the service host instance.
        ///   </para>
        ///   <para>
        ///   It provides the function to access the information in the service.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not found.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="path"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> is not an absolute path.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="path"/> includes either or both
        ///   query and fragment components.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="path"/> is <see langword="null"/>.
        /// </exception>
        public bool TryGetServiceHost(string path, out WebSocketServiceHost host)
        {
            if (path == null)
                throw new ArgumentNullException("path");

            if (path.Length == 0)
                throw new ArgumentException("An empty string.", "path");

            if (path[0] != '/')
            {
                var msg = "Not an absolute path.";

                throw new ArgumentException(msg, "path");
            }

            if (path.IndexOfAny(new[] { '?', '#' }) > -1)
            {
                var msg = "It includes either or both query and fragment components.";

                throw new ArgumentException(msg, "path");
            }

            return InternalTryGetServiceHost(path, out host);
        }
    }
    //========================================================================================
    /// <summary>
    /// Provides the management function for the sessions in a WebSocket service.
    /// </summary>
    /// <remarks>
    /// This class manages the sessions in a WebSocket service provided by the
    /// <see cref="WebSocketServer"/> or <see cref="HttpServer"/> class.
    /// </remarks>
    public class WebSocketSessionManager
    {
        private object _forSweep;
        private volatile bool _keepClean;
        private Logger _log;
        private static readonly byte[] _rawEmptyPingFrame;
        private Dictionary<string, IWebSocketSession> _sessions;
        private volatile ServerState _state;
        private volatile bool _sweeping;
        private System.Timers.Timer _sweepTimer;
        private object _sync;
        private TimeSpan _waitTime;

        static WebSocketSessionManager()
        {
            _rawEmptyPingFrame = WebSocketFrame.CreatePingFrame(false).ToArray();
        }

        internal WebSocketSessionManager(Logger log)
        {
            _log = log;

            _forSweep = new object();
            _sessions = new Dictionary<string, IWebSocketSession>();
            _state = ServerState.Ready;
            _sync = ((ICollection)_sessions).SyncRoot;
            _waitTime = TimeSpan.FromSeconds(1);

            setSweepTimer(60000);
        }

        internal ServerState State
        {
            get
            {
                return _state;
            }
        }

        /// <summary>
        /// Gets the IDs for the active sessions in the WebSocket service.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An <see cref="T:System.Collections.Generic.IEnumerable{string}"/>
        ///   instance.
        ///   </para>
        ///   <para>
        ///   It provides an enumerator which supports the iteration over
        ///   the collection of the IDs for the active sessions.
        ///   </para>
        /// </value>
        public IEnumerable<string> ActiveIDs
        {
            get
            {
                foreach (var res in broadping(_rawEmptyPingFrame))
                {
                    if (res.Value)
                        yield return res.Key;
                }
            }
        }

        /// <summary>
        /// Gets the number of the sessions in the WebSocket service.
        /// </summary>
        /// <value>
        /// An <see cref="int"/> that represents the number of the sessions.
        /// </value>
        public int Count
        {
            get
            {
                lock (_sync)
                    return _sessions.Count;
            }
        }

        /// <summary>
        /// Gets the IDs for the sessions in the WebSocket service.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An <see cref="T:System.Collections.Generic.IEnumerable{string}"/>
        ///   instance.
        ///   </para>
        ///   <para>
        ///   It provides an enumerator which supports the iteration over
        ///   the collection of the IDs for the sessions.
        ///   </para>
        /// </value>
        public IEnumerable<string> IDs
        {
            get
            {
                if (_state != ServerState.Start)
                    return Enumerable.Empty<string>();

                lock (_sync)
                {
                    if (_state != ServerState.Start)
                        return Enumerable.Empty<string>();

                    return _sessions.Keys.ToList();
                }
            }
        }

        /// <summary>
        /// Gets the IDs for the inactive sessions in the WebSocket service.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An <see cref="T:System.Collections.Generic.IEnumerable{string}"/>
        ///   instance.
        ///   </para>
        ///   <para>
        ///   It provides an enumerator which supports the iteration over
        ///   the collection of the IDs for the inactive sessions.
        ///   </para>
        /// </value>
        public IEnumerable<string> InactiveIDs
        {
            get
            {
                foreach (var res in broadping(_rawEmptyPingFrame))
                {
                    if (!res.Value)
                        yield return res.Key;
                }
            }
        }

        /// <summary>
        /// Gets the session instance with the specified ID.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="IWebSocketSession"/> instance that provides
        ///   the function to access the information in the session.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not found.
        ///   </para>
        /// </value>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session to get.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="id"/> is an empty string.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="id"/> is <see langword="null"/>.
        /// </exception>
        public IWebSocketSession this[string id]
        {
            get
            {
                if (id == null)
                    throw new ArgumentNullException("id");

                if (id.Length == 0)
                    throw new ArgumentException("An empty string.", "id");

                IWebSocketSession session;

                tryGetSession(id, out session);

                return session;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the inactive sessions in
        /// the WebSocket service are cleaned up periodically.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the service is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        /// <c>true</c> if the inactive sessions are cleaned up every 60 seconds;
        /// otherwise, <c>false</c>.
        /// </value>
        public bool KeepClean
        {
            get
            {
                return _keepClean;
            }

            set
            {
                lock (_sync)
                {
                    if (!canSet())
                        return;

                    _keepClean = value;
                }
            }
        }

        /// <summary>
        /// Gets the session instances in the WebSocket service.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An <see cref="T:System.Collections.Generic.IEnumerable{IWebSocketSession}"/>
        ///   instance.
        ///   </para>
        ///   <para>
        ///   It provides an enumerator which supports the iteration over
        ///   the collection of the session instances.
        ///   </para>
        /// </value>
        public IEnumerable<IWebSocketSession> Sessions
        {
            get
            {
                if (_state != ServerState.Start)
                    return Enumerable.Empty<IWebSocketSession>();

                lock (_sync)
                {
                    if (_state != ServerState.Start)
                        return Enumerable.Empty<IWebSocketSession>();

                    return _sessions.Values.ToList();
                }
            }
        }

        /// <summary>
        /// Gets or sets the time to wait for the response to the WebSocket
        /// Ping or Close.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the service is
        /// Ready or Stop.
        /// </remarks>
        /// <value>
        /// A <see cref="TimeSpan"/> that represents the time to wait for
        /// the response.
        /// </value>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The value specified for a set operation is zero or less.
        /// </exception>
        public TimeSpan WaitTime
        {
            get
            {
                return _waitTime;
            }

            set
            {
                if (value <= TimeSpan.Zero)
                {
                    var msg = "Zero or less.";

                    throw new ArgumentOutOfRangeException("value", msg);
                }

                lock (_sync)
                {
                    if (!canSet())
                        return;

                    _waitTime = value;
                }
            }
        }

        private void broadcast(Opcode opcode, byte[] data, Action completed)
        {
            var cache = new Dictionary<CompressionMethod, byte[]>();

            try
            {
                foreach (var session in Sessions)
                {
                    if (_state != ServerState.Start)
                    {
                        _log.Error("The send is cancelled.");

                        break;
                    }

                    session.WebSocket.Send(opcode, data, cache);
                }

                if (completed != null)
                    completed();
            }
            catch (Exception ex)
            {
                _log.Error(ex.Message);
                _log.Debug(ex.ToString());
            }
            finally
            {
                cache.Clear();
            }
        }

        private void broadcast(
          Opcode opcode,
          Stream sourceStream,
          Action completed
        )
        {
            var cache = new Dictionary<CompressionMethod, Stream>();

            try
            {
                foreach (var session in Sessions)
                {
                    if (_state != ServerState.Start)
                    {
                        _log.Error("The send is cancelled.");

                        break;
                    }

                    session.WebSocket.Send(opcode, sourceStream, cache);
                }

                if (completed != null)
                    completed();
            }
            catch (Exception ex)
            {
                _log.Error(ex.Message);
                _log.Debug(ex.ToString());
            }
            finally
            {
                foreach (var cached in cache.Values)
                    cached.Dispose();

                cache.Clear();
            }
        }

        private void broadcastAsync(Opcode opcode, byte[] data, Action completed)
        {
            ThreadPool.QueueUserWorkItem(
              state => broadcast(opcode, data, completed)
            );
        }

        private void broadcastAsync(
          Opcode opcode,
          Stream sourceStream,
          Action completed
        )
        {
            ThreadPool.QueueUserWorkItem(
              state => broadcast(opcode, sourceStream, completed)
            );
        }

        private Dictionary<string, bool> broadping(byte[] rawFrame)
        {
            var ret = new Dictionary<string, bool>();

            foreach (var session in Sessions)
            {
                if (_state != ServerState.Start)
                {
                    ret.Clear();

                    break;
                }

                var res = session.WebSocket.Ping(rawFrame);

                ret.Add(session.ID, res);
            }

            return ret;
        }

        private bool canSet()
        {
            return _state == ServerState.Ready || _state == ServerState.Stop;
        }

        private static string createID()
        {
            return Guid.NewGuid().ToString("N");
        }

        private void setSweepTimer(double interval)
        {
            _sweepTimer = new System.Timers.Timer(interval);
            _sweepTimer.Elapsed += (sender, e) => Sweep();
        }

        private void stop(PayloadData payloadData, bool send)
        {
            var rawFrame = send
                           ? WebSocketFrame
                             .CreateCloseFrame(payloadData, false)
                             .ToArray()
                           : null;

            lock (_sync)
            {
                _state = ServerState.ShuttingDown;
                _sweepTimer.Enabled = false;

                foreach (var session in _sessions.Values.ToList())
                    session.WebSocket.Close(payloadData, rawFrame);

                _state = ServerState.Stop;
            }
        }

        private bool tryGetSession(string id, out IWebSocketSession session)
        {
            session = null;

            if (_state != ServerState.Start)
                return false;

            lock (_sync)
            {
                if (_state != ServerState.Start)
                    return false;

                return _sessions.TryGetValue(id, out session);
            }
        }

        internal string Add(IWebSocketSession session)
        {
            lock (_sync)
            {
                if (_state != ServerState.Start)
                    return null;

                var id = createID();

                _sessions.Add(id, session);

                return id;
            }
        }

        internal bool Remove(string id)
        {
            lock (_sync)
                return _sessions.Remove(id);
        }

        internal void Start()
        {
            lock (_sync)
            {
                _sweepTimer.Enabled = _keepClean;
                _state = ServerState.Start;
            }
        }

        internal void Stop(ushort code, string reason)
        {
            if (code == 1005)
            {
                stop(PayloadData.Empty, true);

                return;
            }

            var payloadData = new PayloadData(code, reason);
            var send = !code.IsReservedStatusCode();

            stop(payloadData, send);
        }

        /// <summary>
        /// Sends the specified data to every client in the WebSocket service.
        /// </summary>
        /// <param name="data">
        /// An array of <see cref="byte"/> that specifies the binary data to send.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The current state of the service is not Start.
        /// </exception>
        public void Broadcast(byte[] data)
        {
            if (_state != ServerState.Start)
            {
                var msg = "The current state of the service is not Start.";

                throw new InvalidOperationException(msg);
            }

            if (data == null)
                throw new ArgumentNullException("data");

            if (data.LongLength <= WebSocket.FragmentLength)
                broadcast(Opcode.Binary, data, null);
            else
                broadcast(Opcode.Binary, new MemoryStream(data), null);
        }

        /// <summary>
        /// Sends the specified data to every client in the WebSocket service.
        /// </summary>
        /// <param name="data">
        /// A <see cref="string"/> that specifies the text data to send.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="data"/> could not be UTF-8-encoded.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The current state of the service is not Start.
        /// </exception>
        public void Broadcast(string data)
        {
            if (_state != ServerState.Start)
            {
                var msg = "The current state of the service is not Start.";

                throw new InvalidOperationException(msg);
            }

            if (data == null)
                throw new ArgumentNullException("data");

            byte[] bytes;

            if (!data.TryGetUTF8EncodedBytes(out bytes))
            {
                var msg = "It could not be UTF-8-encoded.";

                throw new ArgumentException(msg, "data");
            }

            if (bytes.LongLength <= WebSocket.FragmentLength)
                broadcast(Opcode.Text, bytes, null);
            else
                broadcast(Opcode.Text, new MemoryStream(bytes), null);
        }

        /// <summary>
        /// Sends the data from the specified stream instance to every client in
        /// the WebSocket service.
        /// </summary>
        /// <param name="stream">
        ///   <para>
        ///   A <see cref="Stream"/> instance from which to read the data to send.
        ///   </para>
        ///   <para>
        ///   The data is sent as the binary data.
        ///   </para>
        /// </param>
        /// <param name="length">
        /// An <see cref="int"/> that specifies the number of bytes to send.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="stream"/> cannot be read.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is less than 1.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   No data could be read from <paramref name="stream"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="stream"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The current state of the service is not Start.
        /// </exception>
        public void Broadcast(Stream stream, int length)
        {
            if (_state != ServerState.Start)
            {
                var msg = "The current state of the service is not Start.";

                throw new InvalidOperationException(msg);
            }

            if (stream == null)
                throw new ArgumentNullException("stream");

            if (!stream.CanRead)
            {
                var msg = "It cannot be read.";

                throw new ArgumentException(msg, "stream");
            }

            if (length < 1)
            {
                var msg = "Less than 1.";

                throw new ArgumentException(msg, "length");
            }

            var bytes = stream.ReadBytes(length);
            var len = bytes.Length;

            if (len == 0)
            {
                var msg = "No data could be read from it.";

                throw new ArgumentException(msg, "stream");
            }

            if (len < length)
            {
                var fmt = "Only {0} byte(s) of data could be read from the stream.";
                var msg = String.Format(fmt, len);

                _log.Warn(msg);
            }

            if (len <= WebSocket.FragmentLength)
                broadcast(Opcode.Binary, bytes, null);
            else
                broadcast(Opcode.Binary, new MemoryStream(bytes), null);
        }

        /// <summary>
        /// Sends the specified data to every client in the WebSocket service
        /// asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="data">
        /// An array of <see cref="byte"/> that specifies the binary data to send.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="Action"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the send is complete.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The current state of the service is not Start.
        /// </exception>
        public void BroadcastAsync(byte[] data, Action completed)
        {
            if (_state != ServerState.Start)
            {
                var msg = "The current state of the service is not Start.";

                throw new InvalidOperationException(msg);
            }

            if (data == null)
                throw new ArgumentNullException("data");

            if (data.LongLength <= WebSocket.FragmentLength)
                broadcastAsync(Opcode.Binary, data, completed);
            else
                broadcastAsync(Opcode.Binary, new MemoryStream(data), completed);
        }

        /// <summary>
        /// Sends the specified data to every client in the WebSocket service
        /// asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="data">
        /// A <see cref="string"/> that specifies the text data to send.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="Action"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the send is complete.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="data"/> could not be UTF-8-encoded.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The current state of the service is not Start.
        /// </exception>
        public void BroadcastAsync(string data, Action completed)
        {
            if (_state != ServerState.Start)
            {
                var msg = "The current state of the service is not Start.";

                throw new InvalidOperationException(msg);
            }

            if (data == null)
                throw new ArgumentNullException("data");

            byte[] bytes;

            if (!data.TryGetUTF8EncodedBytes(out bytes))
            {
                var msg = "It could not be UTF-8-encoded.";

                throw new ArgumentException(msg, "data");
            }

            if (bytes.LongLength <= WebSocket.FragmentLength)
                broadcastAsync(Opcode.Text, bytes, completed);
            else
                broadcastAsync(Opcode.Text, new MemoryStream(bytes), completed);
        }

        /// <summary>
        /// Sends the data from the specified stream instance to every client in
        /// the WebSocket service asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="stream">
        ///   <para>
        ///   A <see cref="Stream"/> instance from which to read the data to send.
        ///   </para>
        ///   <para>
        ///   The data is sent as the binary data.
        ///   </para>
        /// </param>
        /// <param name="length">
        /// An <see cref="int"/> that specifies the number of bytes to send.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="Action"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the send is complete.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="stream"/> cannot be read.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is less than 1.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   No data could be read from <paramref name="stream"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="stream"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The current state of the service is not Start.
        /// </exception>
        public void BroadcastAsync(Stream stream, int length, Action completed)
        {
            if (_state != ServerState.Start)
            {
                var msg = "The current state of the service is not Start.";

                throw new InvalidOperationException(msg);
            }

            if (stream == null)
                throw new ArgumentNullException("stream");

            if (!stream.CanRead)
            {
                var msg = "It cannot be read.";

                throw new ArgumentException(msg, "stream");
            }

            if (length < 1)
            {
                var msg = "Less than 1.";

                throw new ArgumentException(msg, "length");
            }

            var bytes = stream.ReadBytes(length);
            var len = bytes.Length;

            if (len == 0)
            {
                var msg = "No data could be read from it.";

                throw new ArgumentException(msg, "stream");
            }

            if (len < length)
            {
                var fmt = "Only {0} byte(s) of data could be read from the stream.";
                var msg = String.Format(fmt, len);

                _log.Warn(msg);
            }

            if (len <= WebSocket.FragmentLength)
                broadcastAsync(Opcode.Binary, bytes, completed);
            else
                broadcastAsync(Opcode.Binary, new MemoryStream(bytes), completed);
        }

        /// <summary>
        /// Closes the session with the specified ID.
        /// </summary>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session to close.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="id"/> is an empty string.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="id"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The session could not be found.
        /// </exception>
        public void CloseSession(string id)
        {
            IWebSocketSession session;

            if (!TryGetSession(id, out session))
            {
                var msg = "The session could not be found.";

                throw new InvalidOperationException(msg);
            }

            session.WebSocket.Close();
        }

        /// <summary>
        /// Closes the session with the specified ID, status code, and reason.
        /// </summary>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session to close.
        /// </param>
        /// <param name="code">
        ///   <para>
        ///   A <see cref="ushort"/> that specifies the status code indicating
        ///   the reason for the close.
        ///   </para>
        ///   <para>
        ///   The status codes are defined in
        ///   <see href="http://tools.ietf.org/html/rfc6455#section-7.4">
        ///   Section 7.4</see> of RFC 6455.
        ///   </para>
        /// </param>
        /// <param name="reason">
        ///   <para>
        ///   A <see cref="string"/> that specifies the reason for the close.
        ///   </para>
        ///   <para>
        ///   Its size must be 123 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="id"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is 1010 (mandatory extension).
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is 1005 (no status) and
        ///   <paramref name="reason"/> is specified.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="reason"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="id"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <para>
        ///   <paramref name="code"/> is less than 1000 or greater than 4999.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The size of <paramref name="reason"/> is greater than 123 bytes.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The session could not be found.
        /// </exception>
        public void CloseSession(string id, ushort code, string reason)
        {
            IWebSocketSession session;

            if (!TryGetSession(id, out session))
            {
                var msg = "The session could not be found.";

                throw new InvalidOperationException(msg);
            }

            session.WebSocket.Close(code, reason);
        }

        /// <summary>
        /// Closes the session with the specified ID, status code, and reason.
        /// </summary>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session to close.
        /// </param>
        /// <param name="code">
        ///   <para>
        ///   One of the <see cref="CloseStatusCode"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the status code indicating the reason for the close.
        ///   </para>
        /// </param>
        /// <param name="reason">
        ///   <para>
        ///   A <see cref="string"/> that specifies the reason for the close.
        ///   </para>
        ///   <para>
        ///   Its size must be 123 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="id"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is an undefined enum value.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.MandatoryExtension"/>.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.NoStatus"/> and
        ///   <paramref name="reason"/> is specified.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="reason"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="id"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The size of <paramref name="reason"/> is greater than 123 bytes.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The session could not be found.
        /// </exception>
        public void CloseSession(string id, CloseStatusCode code, string reason)
        {
            IWebSocketSession session;

            if (!TryGetSession(id, out session))
            {
                var msg = "The session could not be found.";

                throw new InvalidOperationException(msg);
            }

            session.WebSocket.Close(code, reason);
        }

        /// <summary>
        /// Sends a ping to the client using the specified session.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the send has successfully done and a pong has been
        /// received within a time; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="id"/> is an empty string.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="id"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The session could not be found.
        /// </exception>
        public bool PingTo(string id)
        {
            IWebSocketSession session;

            if (!TryGetSession(id, out session))
            {
                var msg = "The session could not be found.";

                throw new InvalidOperationException(msg);
            }

            return session.WebSocket.Ping();
        }

        /// <summary>
        /// Sends a ping with the specified message to the client using
        /// the specified session.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the send has successfully done and a pong has been
        /// received within a time; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="message">
        ///   <para>
        ///   A <see cref="string"/> that specifies the message to send.
        ///   </para>
        ///   <para>
        ///   Its size must be 125 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="id"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="message"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="id"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The size of <paramref name="message"/> is greater than 125 bytes.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// The session could not be found.
        /// </exception>
        public bool PingTo(string message, string id)
        {
            IWebSocketSession session;

            if (!TryGetSession(id, out session))
            {
                var msg = "The session could not be found.";

                throw new InvalidOperationException(msg);
            }

            return session.WebSocket.Ping(message);
        }

        /// <summary>
        /// Sends the specified data to the client using the specified session.
        /// </summary>
        /// <param name="data">
        /// An array of <see cref="byte"/> that specifies the binary data to send.
        /// </param>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session.
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="id"/> is an empty string.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///   <para>
        ///   <paramref name="id"/> is <see langword="null"/>.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="data"/> is <see langword="null"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session could not be found.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        public void SendTo(byte[] data, string id)
        {
            IWebSocketSession session;

            if (!TryGetSession(id, out session))
            {
                var msg = "The session could not be found.";

                throw new InvalidOperationException(msg);
            }

            session.WebSocket.Send(data);
        }

        /// <summary>
        /// Sends the specified data to the client using the specified session.
        /// </summary>
        /// <param name="data">
        /// A <see cref="string"/> that specifies the text data to send.
        /// </param>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="id"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="data"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///   <para>
        ///   <paramref name="id"/> is <see langword="null"/>.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="data"/> is <see langword="null"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session could not be found.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        public void SendTo(string data, string id)
        {
            IWebSocketSession session;

            if (!TryGetSession(id, out session))
            {
                var msg = "The session could not be found.";

                throw new InvalidOperationException(msg);
            }

            session.WebSocket.Send(data);
        }

        /// <summary>
        /// Sends the data from the specified stream instance to the client using
        /// the specified session.
        /// </summary>
        /// <param name="stream">
        ///   <para>
        ///   A <see cref="Stream"/> instance from which to read the data to send.
        ///   </para>
        ///   <para>
        ///   The data is sent as the binary data.
        ///   </para>
        /// </param>
        /// <param name="length">
        /// An <see cref="int"/> that specifies the number of bytes to send.
        /// </param>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session.
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="id"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="stream"/> cannot be read.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is less than 1.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   No data could be read from <paramref name="stream"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///   <para>
        ///   <paramref name="id"/> is <see langword="null"/>.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="stream"/> is <see langword="null"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session could not be found.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        public void SendTo(Stream stream, int length, string id)
        {
            IWebSocketSession session;

            if (!TryGetSession(id, out session))
            {
                var msg = "The session could not be found.";

                throw new InvalidOperationException(msg);
            }

            session.WebSocket.Send(stream, length);
        }

        /// <summary>
        /// Sends the specified data to the client using the specified session
        /// asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="data">
        /// An array of <see cref="byte"/> that specifies the binary data to send.
        /// </param>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="T:System.Action{bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the send is complete.
        ///   </para>
        ///   <para>
        ///   The <see cref="bool"/> parameter passed to the delegate is
        ///   <c>true</c> if the send has successfully done; otherwise,
        ///   <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="id"/> is an empty string.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///   <para>
        ///   <paramref name="id"/> is <see langword="null"/>.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="data"/> is <see langword="null"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session could not be found.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        public void SendToAsync(byte[] data, string id, Action<bool> completed)
        {
            IWebSocketSession session;

            if (!TryGetSession(id, out session))
            {
                var msg = "The session could not be found.";

                throw new InvalidOperationException(msg);
            }

            session.WebSocket.SendAsync(data, completed);
        }

        /// <summary>
        /// Sends the specified data to the client using the specified session
        /// asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="data">
        /// A <see cref="string"/> that specifies the text data to send.
        /// </param>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="T:System.Action{bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the send is complete.
        ///   </para>
        ///   <para>
        ///   The <see cref="bool"/> parameter passed to the delegate is
        ///   <c>true</c> if the send has successfully done; otherwise,
        ///   <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="id"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="data"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///   <para>
        ///   <paramref name="id"/> is <see langword="null"/>.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="data"/> is <see langword="null"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session could not be found.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        public void SendToAsync(string data, string id, Action<bool> completed)
        {
            IWebSocketSession session;

            if (!TryGetSession(id, out session))
            {
                var msg = "The session could not be found.";

                throw new InvalidOperationException(msg);
            }

            session.WebSocket.SendAsync(data, completed);
        }

        /// <summary>
        /// Sends the data from the specified stream instance to the client using
        /// the specified session asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="stream">
        ///   <para>
        ///   A <see cref="Stream"/> instance from which to read the data to send.
        ///   </para>
        ///   <para>
        ///   The data is sent as the binary data.
        ///   </para>
        /// </param>
        /// <param name="length">
        /// An <see cref="int"/> that specifies the number of bytes to send.
        /// </param>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="T:System.Action{bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It specifies the delegate called when the send is complete.
        ///   </para>
        ///   <para>
        ///   The <see cref="bool"/> parameter passed to the delegate is
        ///   <c>true</c> if the send has successfully done; otherwise,
        ///   <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="id"/> is an empty string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="stream"/> cannot be read.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is less than 1.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   No data could be read from <paramref name="stream"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///   <para>
        ///   <paramref name="id"/> is <see langword="null"/>.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="stream"/> is <see langword="null"/>.
        ///   </para>
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The session could not be found.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The current state of the WebSocket interface is not Open.
        ///   </para>
        /// </exception>
        public void SendToAsync(
          Stream stream,
          int length,
          string id,
          Action<bool> completed
        )
        {
            IWebSocketSession session;

            if (!TryGetSession(id, out session))
            {
                var msg = "The session could not be found.";

                throw new InvalidOperationException(msg);
            }

            session.WebSocket.SendAsync(stream, length, completed);
        }

        /// <summary>
        /// Cleans up the inactive sessions in the WebSocket service.
        /// </summary>
        public void Sweep()
        {
            if (_sweeping)
            {
                _log.Trace("The sweep process is already in progress.");

                return;
            }

            lock (_forSweep)
            {
                if (_sweeping)
                {
                    _log.Trace("The sweep process is already in progress.");

                    return;
                }

                _sweeping = true;
            }

            foreach (var id in InactiveIDs)
            {
                if (_state != ServerState.Start)
                    break;

                lock (_sync)
                {
                    if (_state != ServerState.Start)
                        break;

                    IWebSocketSession session;

                    if (!_sessions.TryGetValue(id, out session))
                        continue;

                    var state = session.WebSocket.ReadyState;

                    if (state == WebSocketState.Open)
                    {
                        session.WebSocket.Close(CloseStatusCode.Abnormal);

                        continue;
                    }

                    if (state == WebSocketState.Closing)
                        continue;

                    _sessions.Remove(id);
                }
            }

            lock (_forSweep)
                _sweeping = false;
        }

        /// <summary>
        /// Tries to get the session instance with the specified ID.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the try has succeeded; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="id">
        /// A <see cref="string"/> that specifies the ID of the session to get.
        /// </param>
        /// <param name="session">
        ///   <para>
        ///   When this method returns, a <see cref="IWebSocketSession"/> instance
        ///   that receives the session instance.
        ///   </para>
        ///   <para>
        ///   It provides the function to access the information in the session.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not found.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="id"/> is an empty string.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="id"/> is <see langword="null"/>.
        /// </exception>
        public bool TryGetSession(string id, out IWebSocketSession session)
        {
            if (id == null)
                throw new ArgumentNullException("id");

            if (id.Length == 0)
                throw new ArgumentException("An empty string.", "id");

            return tryGetSession(id, out session);
        }
    }
    //==========================================================================














}
