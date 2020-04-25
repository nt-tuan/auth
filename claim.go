package auth

import (
	"strconv"
	"time"

	"github.com/go-redis/redis"
	"github.com/thanhtuan260593/auth/models"
)

//RedisClaim repos implement IClaimRepository
type RedisClaim struct {
	IClaimRepository
	client *redis.Client
}

//NewRedisClaim func
func NewRedisClaim(client *redis.Client) IClaimRepository {
	return RedisClaim{client: client}
}

//AddClaim implement
func (r RedisClaim) AddClaim(claim *models.Claim) error {
	now := time.Now()
	return r.client.Set(claim.Key, strconv.Itoa(int(claim.UserID)), claim.ExpireAt.Sub(now)).Err()
}

//RemoveClaim implement
func (r RedisClaim) RemoveClaim(claim *models.Claim) error {
	return nil
}

//GetClaim implement
func (r RedisClaim) GetClaim(claim *models.Claim) error {
	rs, err := r.client.Get(claim.Key).Result()
	if err == nil {
		return err
	}
	userID, err := strconv.ParseUint(rs, 10, 32)
	if err != nil {
		return err
	}
	claim.UserID = uint(userID)
	return nil
}
