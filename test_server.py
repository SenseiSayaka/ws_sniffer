import asyncio
import websockets
import json
from datetime import datetime

connected_clients = set()

async def echo_handler(websocket):
    """Обработчик WebSocket соединений"""
    client_id = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
    connected_clients.add(websocket)
    print(f"   Клиент подключен: {client_id}")
    print(f"   Всего клиентов: {len(connected_clients)}")
    
    try:
        async for message in websocket:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"\n📨 [{timestamp}] Получено от {client_id}:")
            print(f"   {message[:100]}...")
            
            # Эхо-ответ
            response = {
                "type": "echo",
                "original": message,
                "timestamp": timestamp,
                "client": client_id,
                "server": "Test WebSocket Server v1.0"
            }
            
            await websocket.send(json.dumps(response, ensure_ascii=False))
            print(f"   Отправлен ответ клиенту {client_id}")
            
            # Broadcast другим клиентам
            if len(connected_clients) > 1:
                broadcast_msg = {
                    "type": "broadcast",
                    "from": client_id,
                    "message": message,
                    "timestamp": timestamp
                }
                
                disconnected = set()
                for client in connected_clients:
                    if client != websocket:
                        try:
                            await client.send(json.dumps(broadcast_msg, ensure_ascii=False))
                        except:
                            disconnected.add(client)
                
                connected_clients.difference_update(disconnected)
                
    except websockets.exceptions.ConnectionClosed:
        print(f"   Клиент отключен: {client_id}")
    finally:
        connected_clients.discard(websocket)
        print(f"   Осталось клиентов: {len(connected_clients)}")


async def main():
    print("╔════════════════════════════════════════╗")
    print("║   WebSocket Test Server                ║")
    print("╚════════════════════════════════════════╝")
    print()
    print("   Запуск сервера...")
    
    # Запуск на localhost:8765
    async with websockets.serve(echo_handler, "0.0.0.0", 8765):
        print("   Сервер запущен на ws://localhost:8765")
        print("   Ожидание подключений...")
        print("   (Ctrl+C для остановки)")
        print()
        
        # Работаем вечно
        await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n🛑 Сервер остановлен")
