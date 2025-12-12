securechat/
├── app.py                     # Flask 主应用入口
├── config.py                  # 配置文件（SECRET_KEY 等）
├── requirements.txt           # 依赖包
├── instance/
│   └── chat.db                # SQLite 数据库（运行时生成）
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── chat.js            # 前端 Socket.IO 逻辑 + 加密
├── templates/
│   ├── base.html              # 基础模板
│   ├── login.html
│   ├── register.html
│   ├── create_room.html       # 创建房间页面
│   └── chat_room.html         # 聊天界面（核心）
├── models.py                  # 用户、房间模型（SQLAlchemy）
├── auth.py                    # 注册/登录路由与逻辑
├── chat.py                    # 聊天室路由 + Socket.IO 事件处理
└── utils/
    ├── crypto.py              # （可选）后端辅助加密工具
    └── room_manager.py        # 房间状态管理（内存 or DB）
