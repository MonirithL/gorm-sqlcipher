module github.com/MonirithL/gorm-sqlcipher

go 1.24.0

replace github.com/MonirithL/gorm-sqlcipher/sqlite3 => ./sqlite3

require (
	github.com/MonirithL/gorm-sqlcipher/sqlite3 v0.0.0-00010101000000-000000000000
	gorm.io/gorm v1.31.0
)

require (
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	golang.org/x/text v0.20.0 // indirect
)
