using System;
using ScriptEngine.Machine.Contexts;
using ScriptEngine.Machine;
using ScriptEngine.HostedScript.Library;

//namespace Hik.Communication.Scs.Communication.Messages
//{
//    // Сохраняет сообщение, которое будет использоваться событием.
//    public class MessageEventArgs : System.EventArgs
//    {
//        // Объект сообщение, связанный с этим событием.
//        public IScsMessage Message { get; private set; }

//        // Создает новый объект MessageEventArgs.
//        // "message" - Объект сообщение, связанный с этим событием.
//        public MessageEventArgs(IScsMessage message)
//        {
//            Message = message;
//        }
//    }
//}

namespace WebSocketSharp
{
    /// <summary>
    /// Представляет данные события для <see cref="WebSocket.OnMessage"/> события.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///   Событие происходит, когда интерфейс <см. Cref = "webSocket"/>
    ///   получает сообщение или пинг, если <см. cref = "websocket.emitonping"/>
    ///   свойство установлено на <c> true </c>.
    ///   </para>
    ///   <para>
    ///   Если вы хотите получить данные сообщения, вам следует получить доступ
    ///   к свойству <see cref="Data"/> или свойству <see cref="RawData"/>.
    ///   </para>
    /// </remarks>
    public class MessageEventArgs : EventArgs
    {
        private string _data;
        private bool _dataSet;
        private Opcode _opcode;
        private byte[] _rawData;

        internal MessageEventArgs(WebSocketFrame frame)
        {
            _opcode = frame.Opcode;
            _rawData = frame.PayloadData.ApplicationData;
        }

        internal MessageEventArgs(Opcode opcode, byte[] rawData)
        {
            if ((ulong)rawData.LongLength > PayloadData.MaxLength)
                throw new WebSocketException(CloseStatusCode.TooBig);

            _opcode = opcode;
            _rawData = rawData;
        }

        /// <summary>
        /// Получает opcode для сообщения.
        /// </summary>
        /// <value>
        /// <see cref="Opcode.Text"/>, <see cref="Opcode.Binary"/>,
        /// or <see cref="Opcode.Ping"/>.
        /// </value>
        internal Opcode Opcode
        {
            get
            {
                return _opcode;
            }
        }

        /// <summary>
        /// Получает данные сообщения как <see cref="string"/>.
        /// </summary>
        /// <value>
        ///   <para>
        ///   Это <see cref="string"/> представляет данные сообщения, если тип сообщения является 
        ///   текстом или пингом.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> Если тип сообщения является двоичным, или данные сообщения 
        ///   не могут быть UTF-8-декодированными.
        ///   </para>
        /// </value>
        public string Data
        {
            get
            {
                setData();

                return _data;
            }
        }

        /// <summary>
        /// Получает значение, указывающее, является ли тип сообщения двоичным.
        /// </summary>
        /// <value>
        /// <c>true</c> Если тип сообщения является двоичным; в противном случае, <c>false</c>.
        /// </value>
        public bool IsBinary
        {
            get
            {
                return _opcode == Opcode.Binary;
            }
        }

        /// <summary>
        /// Получает значение, указывающее, является ли тип сообщения Ping.
        /// </summary>
        /// <value>
        /// <c>true</c> Если тип сообщения пинг; в противном случае, <c>false</c>.
        /// </value>
        public bool IsPing
        {
            get
            {
                return _opcode == Opcode.Ping;
            }
        }

        /// <summary>
        /// Получает значение, указывающее, является ли тип сообщения текстом.
        /// </summary>
        /// <value>
        /// <c>true</c> Если тип сообщения является текстом; в противном случае, <c>false</c>.
        /// </value>
        public bool IsText
        {
            get
            {
                return _opcode == Opcode.Text;
            }
        }

        /// <summary>
        /// Получает данные сообщения как массив <see cref="byte"/>.
        /// </summary>
        /// <value>
        /// Массив <see cref="byte"/> представляющий данные сообщения.
        /// </value>
        public byte[] RawData
        {
            get
            {
                setData();

                return _rawData;
            }
        }

        private void setData()
        {
            if (_dataSet)
                return;

            if (_opcode == Opcode.Binary)
            {
                _dataSet = true;

                return;
            }

            string data;

            if (_rawData.TryGetUTF8DecodedString(out data))
                _data = data;

            _dataSet = true;
        }
    }

}

namespace OSWebSocket
{
    [ContextClass("СвСообщениеАрг", "SwMessageEventArgs")]
    public class SwMessageEventArgs : AutoContext<SwMessageEventArgs>
    {
        public SwMessageEventArgs()
        {
        }

        public IValue sender = null;
        [ContextProperty("Отправитель", "Sender")]
        public IValue Sender
        {
            get { return sender; }
        }

        public IValue eventAction = null;
        [ContextProperty("Действие", "EventAction")]
        public IValue EventAction
        {
            get { return eventAction; }
        }

        public IValue parameter = null;
        [ContextProperty("Параметр", "Parameter")]
        public IValue Parameter
        {
            get { return parameter; }
        }

        public string message;
        [ContextProperty("Сообщение", "Message")]
        public string Message
        {
            get { return message; }
        }
    }
}
