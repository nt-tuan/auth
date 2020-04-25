package models

import (
	"time"
)

//Claim contains expiration of user claim
type Claim struct {
	Key      string `gorm:"type:uuid;primary_key"`
	UserID   uint
	ExpireAt *time.Time
}

//TokenDetails to be hashed
type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUUID   string
	RefreshUUID  string
	AtExpires    int64
	RtExpires    int64
}

//AccessDetails stored in jwt
type AccessDetails struct {
	AccessUUID string
	UserID     uint
	AtExpires  *time.Time
}

//RefreshDetails stored in jwt
type RefreshDetails struct {
	RefreshUUID string
	UserID      uint
}
