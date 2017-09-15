--DECLARE @FirstfileName sysname
--SELECT @FirstfileName=name FROM tempdb..sysfiles WHERE fileid = 1
--IF @FirstfileName = 'tempdev'
--BEGIN
--	ALTER DATABASE [tempdb] MODIFY FILE ( NAME = N'tempdev', NEWNAME=N'tempdev1')
--	ALTER DATABASE [tempdb] MODIFY FILE ( NAME = N'tempdev1', SIZE = ##TempDBEachDataFileSize##KB , FILEGROWTH = 0 )
--	ALTER DATABASE [tempdb] MODIFY FILE ( NAME = N'templog', SIZE = 1048576KB , FILEGROWTH = 1048576KB , MAXSIZE = ##TempDBLogFileSize##KB )
--END
--ELSE
--BEGIN
--	ALTER DATABASE [tempdb] MODIFY FILE ( NAME = N'tempdev1', SIZE = ##TempDBEachDataFileSize##KB , FILEGROWTH = 0 )
--	ALTER DATABASE [tempdb] MODIFY FILE ( NAME = N'templog', SIZE = 1048576KB , FILEGROWTH = 1048576KB , MAXSIZE = ##TempDBLogFileSize##KB )
--END
IF NOT EXISTS (SELECT TOP 1 NAME FROM tempdb..sysfiles where name = '##newname##')
BEGIN
	ALTER DATABASE [tempdb] MODIFY FILE ( NAME = N'##name##', NEWNAME=N'##newname##')
END
ALTER DATABASE [tempdb] MODIFY FILE ( NAME = N'##newname##', SIZE = ##TempDBEachDataFileSize##KB , FILEGROWTH = 0 )