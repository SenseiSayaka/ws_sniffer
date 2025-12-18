import asyncio
import websockets
import json
import sys

async def test_client():
    uri = "ws://localhost:8765"
    
    print("╔══════════════════════════════════════════╗")
    print("║  WebSocket Test Client                  ║")
    print("╚══════════════════════════════════════════╝")
    print()
    print(f"  Подключение к {uri}...")
    
    try:
        async with websockets.connect(uri, compression=None) as websocket:
            print("   Подключено!")
            print("   Введите сообщение для отправки (или 'quit' для выхода)")
            print()
            
            # Создаем задачу для получения сообщений
            async def receive_messages():
                try:
                    async for message in websocket:
                        data = json.loads(message)
                        msg_type = data.get('type', 'unknown')
                        
                        if msg_type == 'welcome':
                            print(f"   Сервер: {data['message']}")
                        elif msg_type == 'echo':
                            print(f"   Эхо: {data['original']}")
                        elif msg_type == 'broadcast':
                            print(f"   [{data['from']}]: {data['message']}")
                        elif msg_type == 'periodic':
                            print(f"   {data['message']} (клиентов: {data['active_clients']})")
                        else:
                            print(f"   Получено: {message}")
                        
                        print(">> ", end='', flush=True)
                except websockets.exceptions.ConnectionClosed:
                    print("\n   Соединение закрыто сервером")
            
            # Запускаем прием сообщений в фоне
            receive_task = asyncio.create_task(receive_messages())
            
            # Отправляем тестовые сообщения
            test_messages = [
                "Привет, сервер!",
                "Это тестовое сообщение для снифера",
                json.dumps({"action": "test", "data": "JSON сообщение"}, ensure_ascii=False),
                "Сообщение с эмодзи 🚀🔥💻",
                "Кириллица: АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
            ]
            
            print("   Режим работы:")
            print("1. Автоматический (отправка тестовых сообщений)")
            print("2. Ручной (вводить сообщения самостоятельно)")
            mode = input("Выберите режим (1/2): ").strip()
            
            if mode == '1':
                print("\n  Отправка тестовых сообщений...\n")
                for i, msg in enumerate(test_messages, 1):
                    await asyncio.sleep(2)
                    print(f"[{i}/{len(test_messages)}] Отправка: {msg[:50]}...")
                    await websocket.send(msg)
                
                print("\n  Все тестовые сообщения отправлены!")
                print("\n  Ожидание еще 10 секунд для получения ответов...")
                await asyncio.sleep(10)
                
            else:
                # Ручной режим
                while True:
                    try:
                        message = await asyncio.get_event_loop().run_in_executor(
                            None, input, ">> "
                        )
                        
                        if message.lower() in ['quit', 'exit', 'q']:
                            print("  Выход...")
                            break
                        
                        if message.strip():
                            await websocket.send(message)
                            print(f"  отправлено: {message}")
                    
                    except EOFError:
                        break
            
            receive_task.cancel()
            
    except ConnectionRefusedError:
        print("   Ошибка: Не удается подключиться к серверу")
        print("   Убедитесь, что сервер запущен на ws://localhost:8765")
    except Exception as e:
        print(f"   Ошибка: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(test_client())
    except KeyboardInterrupt:
        print("\n  Клиент остановлен")
