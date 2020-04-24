package auth

import (
	"time"

	"github.com/jinzhu/gorm"
)

//Account db model
type Account struct {
	*gorm.Model
	Username          string `gorm:"type:varchar(100);unique_index"`
	Email             string `gorm:"type:varchar(100);unique_index"`
	EmailConfirmed    bool
	PasswordHash      string `gorm:"type:varchar(max);index"`
	SecurityStamp     string `gorm:"type:varchar(max)"`
	AccessFailedCount uint
	LockoutEnabled    bool
	LockoutEnd        *time.Time
	//Product changes approval
}
