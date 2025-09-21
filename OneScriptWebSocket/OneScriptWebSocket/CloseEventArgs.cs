using System;
using ScriptEngine.Machine.Contexts;
using ScriptEngine.Machine;
using ScriptEngine.HostedScript.Library;

namespace WebSocketSharp
{
    // Представляет данные о событии для события <see Cref = "WebSocket.OnClose"/>.
    //   <para>
    //   Закрытие происходит, когда соединение WebSocket было закрыто.
    //   </para>
    //   <para>
    //   Если вы хотите получить причину закрытия соединения, вам следует получить доступ к <see cref="Code"/> или <see cref="Reason"/> свойству.
    //   </para>
    public class CloseEventArgs : EventArgs
    {
        private PayloadData _payloadData;
        private bool _wasClean;

        internal CloseEventArgs(PayloadData payloadData, bool clean)
        {
            _payloadData = payloadData;
            _wasClean = clean;
        }

        // Получает код состояния для закрытия соединения.
        // <value>
        //   <para>
        //   Это <see cref="ushort"/>  представляет код состояния для закрытия соединения.
        //   </para>
        //   <para>
        //   1005 (no status) если нет.
        //   </para>
        // </value>
        public ushort Code
        {
            get
            {
                return _payloadData.Code;
            }
        }

        // Получает причину для закрытия соединения.
        // <value>
        //   <para>
        //   Это <see cref="string"/>  представляет собой причину закрытия соединения.
        //   </para>
        //   <para>
        //   Пустая строка, если нет.
        //   </para>
        // </value>
        public string Reason
        {
            get
            {
                return _payloadData.Reason;
            }
        }

        // Получает значение, указывающее, было ли соединение закрыто чисто.
        // <value>
        // <c>true</c> Если соединение было закрыто чисто; в противном случае, <c>false</c>.
        // </value>
        public bool WasClean
        {
            get
            {
                return _wasClean;
            }
        }
    }
}

namespace OSWebSocket
{
    [ContextClass("СвПриОтключенииАрг", "SwCloseEventArgs")]
    public class SwCloseEventArgs : AutoContext<SwCloseEventArgs>
    {
        public SwCloseEventArgs()
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

        public int code;
        [ContextProperty("КодЗакрытия", "Code")]
        public int Code
        {
            get { return code; }
        }

        public string reason;
        [ContextProperty("ПричинаЗакрытия", "Reason")]
        public string Reason
        {
            get { return reason; }
        }

        public bool wasClean;
        [ContextProperty("ЧистоеЗакрытие", "WasClean")]
        public bool WasClean
        {
            get { return wasClean; }
        }
    }
}
