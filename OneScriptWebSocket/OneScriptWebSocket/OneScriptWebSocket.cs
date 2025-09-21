using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ScriptEngine.Machine;
using ScriptEngine.Machine.Contexts;
using ScriptEngine.HostedScript.Library;
using ScriptEngine.HostedScript.Library.Binary;
using System.Collections.Concurrent;

namespace OSWebSocket
{
    [ContextClass("ВебСокетДляОдноСкрипта", "OneScriptWebSocket")]
    public class OneScriptWebSocket : AutoContext<OneScriptWebSocket>
    {
        public static dynamic Event = null;
        public static SwAction EventAction = null;
        public static ConcurrentQueue<dynamic> EventQueue = new ConcurrentQueue<dynamic>();
        public static OneScriptWebSocket instance;
        private static StructureImpl shareStructure = new StructureImpl();
        public static string separator = Path.DirectorySeparatorChar.ToString();
        public static IRuntimeContextInstance startupScript = GlobalContext().StartupScript();
        public static string fullPathStartupScript = startupScript.GetPropValue(startupScript.FindProperty("Source")).AsString();
        public static string pathStartupScript = startupScript.GetPropValue(startupScript.FindProperty("Path")).AsString();
        public static string nameStartupScript = fullPathStartupScript.Replace(pathStartupScript, "").Replace(".os", "").Replace(separator, "");

        [ScriptConstructor]
        public static IRuntimeContextInstance Constructor()
        {
            instance = new OneScriptWebSocket();
            instance.InjectGlobalProperty(shareStructure, "ОбщаяСтруктура", false);
            shareStructure.Insert("ВСДОС", instance);
            return instance;
        }

        [ContextMethod("ВвестиГлобальноеСвойство", "InjectGlobalProperty")]
        public void InjectGlobalProperty(IValue obj, string name, bool onlyRead)
        {
            GlobalContext().EngineInstance.Environment.InjectGlobalProperty(obj, name, onlyRead);
        }

        public static SystemGlobalContext GlobalContext()
        {
            return GlobalsManager.GetGlobalContext<SystemGlobalContext>();
        }

        [ContextMethod("Действие", "Action")]
        public SwAction Action(IRuntimeContextInstance script, string methodName, IValue param = null)
        {
            return new SwAction(script, methodName, param);
        }

        [ContextProperty("АргументыСобытия", "EventArgs")]
        public IValue EventArgs
        {
            get { return Event; }
        }

        [ContextMethod("ПолучитьСобытие", "DoEvents")]
        public DelegateAction DoEvents()
        {
            while (EventQueue.Count == 0)
            {
                System.Threading.Thread.Sleep(7);
            }

            IValue Action1 = EventHandling();
            if (Action1.GetType() == typeof(SwAction))
            {
                return DelegateAction.Create(((SwAction)Action1).Script, ((SwAction)Action1).MethodName);
            }
            return (DelegateAction)Action1;
        }

        public static IValue EventHandling()
        {
            dynamic EventArgs1;
            EventQueue.TryDequeue(out EventArgs1);
            Event = EventArgs1;
            EventAction = EventArgs1.EventAction;
            return EventAction;
        }

        public static bool goOn = true;
        [ContextProperty("Продолжать", "GoOn")]
        public bool GoOn
        {
            get { return goOn; }
            set { goOn = value; }
        }

        //        public static bool clientUploaded = false;
        //        public void LoadClient()
        //        {
        //            StructureImpl extContext = new StructureImpl();
        //            extContext.Insert(nameStartupScript, ValueFactory.Create(startupScript));
        //            extContext.Insert("ОбщаяСтруктура", shareStructure);

        //            string backgroundClient = @"
        //Процедура ЗапускКлиента(параметр1) Экспорт
        //	Контекст = Новый Структура(""ВСДОС"", параметр1);
        //	Стр = ""
        //	|
        //	|Процедура ВебСокетКлиент1_ПриПодключении() Экспорт
        //	|	Сообщить(""""ВебСокетКлиент1_ПриПодключении """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	Сообщить(""""==============================="""");
        //	|КонецПроцедуры
        //	|
        //	|Процедура ВебСокетКлиент1_ПриОтключении() Экспорт
        //	|	Сообщить(""""ВебСокетКлиент1_ПриОтключении """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	
        //	|	Сообщить(""""Отправитель = """" + ВСДОС.АргументыСобытия.Отправитель + """"  """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	Сообщить(""""КодЗакрытия = """" + ВСДОС.АргументыСобытия.КодЗакрытия + """"  """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	Сообщить(""""ПричинаЗакрытия = """" + ВСДОС.АргументыСобытия.ПричинаЗакрытия + """"  """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	Сообщить(""""ЧистоеЗакрытие = """" + ВСДОС.АргументыСобытия.ЧистоеЗакрытие + """"  """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	Сообщить(""""==============================="""");
        //	|КонецПроцедуры
        //	|
        //	|Процедура ВебСокетКлиент1_ПриПолученииСообщения() Экспорт
        //	|	Сообщить(""""==============================="""");
        //	|	Сообщить(""""==============================="""");
        //	|	Сообщить(""""ВебСокетКлиент1_ПриПолученииСообщения """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	// Сообщить(""""Отправитель = """" + ВСДОС.АргументыСобытия.Отправитель + """"  """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	// Сообщить(""""Сообщение = """" + ВСДОС.АргументыСобытия.Сообщение + """"  """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	Сообщить(""""==============================="""");
        //	|	Сообщить(""""==============================="""");
        //	|КонецПроцедуры
        //	|
        //	|Процедура ВебСокетКлиент1_ПриОшибке() Экспорт
        //	|	Сообщить(""""ВебСокетКлиент1_ПриОшибке """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	
        //	|	Сообщить(""""ИсключениеОшибки = """" + ВСДОС.АргументыСобытия.ИсключениеОшибки + """"  """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	Сообщить(""""СообщениеОшибки = """" + ВСДОС.АргументыСобытия.СообщениеОшибки + """"  """" + ТекущаяУниверсальнаяДатаВМиллисекундах());
        //	|	Сообщить(""""==============================="""");
        //	|КонецПроцедуры
        //	|
        //	|ВебСокетКлиент1 = ВСДОС.ВебСокетКлиент(""""ws://localhost:4649/Echo"""");
        //	|ВебСокетКлиент1.ПриПодключении = ВСДОС.Действие(ЭтотОбъект, """"ВебСокетКлиент1_ПриПодключении"""");
        //    |ВебСокетКлиент1.ПриОтключении = ВСДОС.Действие(ЭтотОбъект, """"ВебСокетКлиент1_ПриОтключении"""");
        //    |ВебСокетКлиент1.ПриПолученииСообщения = ВСДОС.Действие(ЭтотОбъект, """"ВебСокетКлиент1_ПриПолученииСообщения"""");
        //    |// ВебСокетКлиент1.ПриОшибке = ВСДОС.Действие(ЭтотОбъект, """"ВебСокетКлиент1_ПриОшибке"""");
        //	|
        //	|ВебСокетКлиент1.Подключить();
        //	|Приостановить(5000);
        //	|
        //	|Пока ВСДОС.Продолжать Цикл
        //	|   ВСДОС.ПолучитьСобытие().Выполнить();
        //	|КонецЦикла;
        //	|"";
        //	ЗагрузитьСценарийИзСтроки(Стр, Контекст);
        //КонецПроцедуры

        //МассивПараметров = Новый Массив(1);
        //МассивПараметров[0] = ОбщаяСтруктура.ВСДОС;
        //Задание = ФоновыеЗадания.Выполнить(ЭтотОбъект, ""ЗапускКлиента"", МассивПараметров);
        //";
        //            GlobalContext().LoadScriptFromString(backgroundClient, extContext);
        //            //while (!clientUploaded)
        //            //{
        //            //    System.Threading.Thread.Sleep(300);
        //            //}
        //        }


        [ContextMethod("ВебСокетКлиент", "WebSocketClient")]
        public SwWebSocetClient WebSocetClient(string p1, ArrayImpl p2 = null)
        {
            string backgroundTasksClient = @"
Процедура ЗапускКлиента(параметр1, параметр2) Экспорт
    Контекст = Новый Структура();
    Контекст.Вставить(""ВСДОС"", параметр1);
    Контекст.Вставить(""ВКлиент"", параметр2);
    Стр = ""
    |// ВКлиент.Подключить(); // Подключать в основном скрипте, а не здесь.
    |
    |Пока ВСДОС.Продолжать Цикл
    |	ВСДОС.ПолучитьСобытие().Выполнить();
    |КонецЦикла;
    |"";
    ЗагрузитьСценарийИзСтроки(Стр, Контекст);
КонецПроцедуры

МассивПараметров = Новый Массив(2);
МассивПараметров[0] = ВСДОС;
МассивПараметров[1] = ВКлиент;
Задание = ФоновыеЗадания.Выполнить(ЭтотОбъект, ""ЗапускКлиента"", МассивПараметров);
";
            SwWebSocetClient SwWebSocetClient1 = new SwWebSocetClient(p1, p2);
            StructureImpl extContext = new StructureImpl();
            extContext.Insert("ВКлиент", SwWebSocetClient1);
            extContext.Insert("ВСДОС", instance);
            GlobalContext().LoadScriptFromString(backgroundTasksClient, extContext);

            return SwWebSocetClient1;
        }
    }
}
