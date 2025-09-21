using System;
using ScriptEngine.Machine.Contexts;
using ScriptEngine.Machine;
using ScriptEngine.HostedScript.Library;

namespace OSWebSocket
{
    [ContextClass("СвПриОшибкеАрг", "SwErrorEventArgs")]
    public class SwErrorEventArgs : AutoContext<SwErrorEventArgs>
    {
        public SwErrorEventArgs()
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

        public string errorException;
        [ContextProperty("ИсключениеОшибки", "ErrorException")]
        public string ErrorException
        {
            get { return errorException; }
        }

        public string errorMessage;
        [ContextProperty("СообщениеОшибки", "ErrorMessage")]
        public string ErrorMessage
        {
            get { return errorMessage; }
        }
    }
}
