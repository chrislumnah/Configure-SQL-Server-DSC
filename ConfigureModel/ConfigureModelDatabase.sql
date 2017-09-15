ALTER DATABASE model modify FILE (NAME = modeldev, size = 128mb, filegrowth = 128mb)
GO
ALTER DATABASE model modify FILE (NAME = modellog, size = 128mb, filegrowth = 128mb) 
GO
ALTER DATABASE model SET RECOVERY FULL
GO