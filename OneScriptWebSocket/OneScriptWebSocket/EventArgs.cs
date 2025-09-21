using ScriptEngine.Machine.Contexts;
using ScriptEngine.Machine;
using ScriptEngine.HostedScript.Library;

namespace OSWebSocket
{
    [ContextClass ("СвАргументыСобытия", "SwEventArgs")]
    public class SwEventArgs : AutoContext<SwEventArgs>
    {



        public SwEventArgs()
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











    }
}
