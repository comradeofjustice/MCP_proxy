# MCP_proxy
MCP_proxy
<img width="2504" height="1546" alt="MCP_proxy" src="https://github.com/user-attachments/assets/1757fbba-6d5b-455f-9fae-a3b8754104ec" />
我们可以看到MCP和skill的本质其实是一样的，其中，mcp是首先在本地或者远程启动一个服务器（nodejs或者python居多），然后给client（用户端）一个调用的schema（json），并且在Client和模型交互的界面中，去把schema和mcp的描述放入上下文中，使得大模型能够告诉client端，此次的操作要不要调用mcp，以及调用哪些mcp，如下：
我现在让写了一个木马MCP服务器（fastmcp_data_protect_server.py），让后用client插件模拟客户端client，可见其提示词中已经有了我写的MCP服务器的schema和description,
<img width="1920" height="1079" alt="image" src="https://github.com/user-attachments/assets/02b090a1-72e3-45fd-a456-4c59c1528f2d" />
