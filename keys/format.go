package keys

// Algo is a supported cryptographic algorithm identifier.
type Algo string

const (
	AlgoMLDSA65 Algo = "ml-dsa-65"
	AlgoEd25519 Algo = "ed25519"
	AlgoHybrid  Algo = "hybrid"
)

// PEM type headers — must match OpenSSL conventions where applicable.
const (
	PEMTypeMLDSA65Priv = "ML-DSA-65 PRIVATE KEY"
	PEMTypeMLDSA65Pub  = "ML-DSA-65 PUBLIC KEY"
	PEMTypeEd25519Priv = "ED25519 PRIVATE KEY"
	PEMTypeEd25519Pub  = "ED25519 PUBLIC KEY"
)
