在本项工作中：
需求4：code 269- 310(chat. html)
建立html5local storage，将一个sharedSecret，两个AESKeys（加上两个IVs），两个macKeys，key_history组织成json格式存进去。需要注意的是，我将IV放进AESkey的字典中，同时这些AES，mac全具有两个字典元素用来表达1-2和2-1，在页面打开时调用检索函数，在在密钥交换完成或者在进行refresh之后调用存储函数

需求5：code 209-237( chat. html)
自带的函数，主要修改在：（code 38-65）app.py
 建立一个fetch message函数 和get_messages_for_user，从数据库中进行查询将匹配的消息fetch出来。定义一个端点api来进行数据的处理返回（@app.route('/fetch_messages')），然后传给客户端进行显示渲染


需求6：code 116 - 171（chat. html）
refreshKeys（）函数，包括以下几个分段函数：getKeyForMessage（IV与key对应），时间戳控制，mac验证，从localstorage中获取历史key，获取其他的密钥AES，Mac。

需求7：code331 - 367（chat. html）
当clear的时候，需要判断器，此函数被调用，重新生成共享密钥，同时接受方会受到公钥进行计算生成共享公钥，在将公钥发送到服务器。

需求8：code67-82（app.py）
在服务器中进行json化，存储到SQL中。