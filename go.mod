module github.com/MonirithL/gorm-sqlcipher

go 1.24.0

replace github.com/MonirithL/gorm-sqlcipher/sqlite3 => ./sqlite3

require gorm.io/gorm v1.31.0

require (
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	golang.org/x/text v0.30.0 // indirect
)
