项目骨架
project/
│
├─ app.py              # Flask 主程序
├─ requirements.txt
│
├─ templates/
│    ├─ index.html
│    ├─ login.html
│    ├─ register.html
│    ├─ room.html     # 聊天房间页（WebSocket）
│
├─ static/
│    ├─ styles.css
│    ├─ chat.js       # 前端 WebSocket + 加密逻辑
│
├─ helpers/
│    ├─ crypto.py     # (可选) 加密解密工具
│
├─ database.db
└── rooms.db





