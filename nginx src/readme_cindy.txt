2014-8-26
适合去掉APP_ID的情形，解决了同名应用反部署再被部署后计数会累积的问题。
完成安装后，如果出现不能load applicationList,则在安装目录下手动创建一个，需要有XML文件根元素。
注意该文件的权限，为777才能被php正常访问。（所有者是不是root没关系）

Nginx code modification

1. Newly Added Files
|----------------------------|----------------------------------------------------------|
|File Name                   |Path                                                      |
|----------------------------|----------------------------------------------------------|	 
|ConfServer.c                |src/core                                                  |
|----------------------------|----------------------------------------------------------|
|ConfServer.h    	     |src/core                                                  |
|----------------------------|----------------------------------------------------------|
|drp(directory)              |html/                                                     |
|----------------------------|----------------------------------------------------------|


2. The Modified files 
|----------------------------|----------------------------------------------------------|
|File Name                   |Path                                                      |
|----------------------------|----------------------------------------------------------|	 
|nginx.c                     |src/core/                                                 |
|----------------------------|----------------------------------------------------------|


Tag of the new code:

//--DRPS
//--

//----------------------------DRPS 201308----------------------------------//
changes
//-------------------------------------------------------------------------//





