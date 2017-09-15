IF EXISTS(SELECT 1 FROM tempdb..sysfiles WHERE name = '##tempdevi##')
BEGIN
	ALTER DATABASE [tempdb] MODIFY FILE ( NAME = N'##tempdevi##', SIZE = ##TempDBEachDataFileSize## KB , FILEGROWTH = 0 );
END
ELSE
BEGIN
	ALTER DATABASE [tempdb] ADD FILE ( NAME = N'##tempdevi##', FILENAME = N'##path##.ndf' , SIZE = ##TempDBEachDataFileSize## KB , FILEGROWTH = 0 );
END