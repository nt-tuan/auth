package auth

//IClaimRepository db function
type IClaimRepository interface {
	AddClaim(*Claim) error
	RemoveClaim(*Claim) error
	GetClaim(*Claim) error
}
