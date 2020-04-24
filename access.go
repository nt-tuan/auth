package auth

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
