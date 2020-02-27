package sectorbuilder

import (
	"context"
	"io"

	"github.com/filecoin-project/specs-actors/actors/abi"
	"github.com/ipfs/go-cid"

	ffi "github.com/filecoin-project/filecoin-ffi"
)

type SectorFileType int
const (
	FTUnsealed SectorFileType = 1 << iota
	FTSealed
	FTCache
)

// Interfaces provided by this Package

type Prover interface {
	GenerateEPostCandidates(sectorInfo []abi.SectorInfo, challengeSeed abi.PoStRandomness, faults []abi.SectorNumber) ([]ffi.PoStCandidateWithTicket, error)
	GenerateFallbackPoSt(sectorInfo []abi.SectorInfo, challengeSeed abi.PoStRandomness, faults []abi.SectorNumber) ([]ffi.PoStCandidateWithTicket, []abi.PoStProof, error)
	ComputeElectionPoSt(sectorInfo []abi.SectorInfo, challengeSeed abi.PoStRandomness, winners []abi.PoStCandidate) ([]abi.PoStProof, error)
}

type Sealer interface {
	AddPiece(context.Context, abi.UnpaddedPieceSize, abi.SectorNumber, io.Reader, []abi.UnpaddedPieceSize) (abi.PieceInfo, error)
	SealPreCommit1(ctx context.Context, sectorNum abi.SectorNumber, ticket abi.SealRandomness, pieces []abi.PieceInfo) (out []byte, err error)
	SealPreCommit2(ctx context.Context, sectorNum abi.SectorNumber, phase1Out []byte) (sealedCID cid.Cid, unsealedCID cid.Cid, err error)
	SealCommit1(ctx context.Context, sectorNum abi.SectorNumber, ticket abi.SealRandomness, seed abi.InteractiveSealRandomness, pieces []abi.PieceInfo, sealedCID cid.Cid, unsealedCID cid.Cid) (output []byte, err error)
	SealCommit2(ctx context.Context, sectorNum abi.SectorNumber, phase1Out []byte) (proof []byte, err error)

	// FinalizeSector cleans up cache, and moves it to storage filesystem
	FinalizeSector(context.Context, abi.SectorNumber) error
}

type Validator interface {
	CanCommit(sector SectorPaths) (bool, error)
	CanProve(sector SectorPaths) (Fault, error)

}

type Basic interface {
	SectorSize() abi.SectorSize
	AcquireSectorNumber() (abi.SectorNumber, error)

	Prover
	Sealer

	ReadPieceFromSealedSector(context.Context, abi.SectorNumber, UnpaddedByteIndex, abi.UnpaddedPieceSize, abi.SealRandomness, cid.Cid) (io.ReadCloser, error)
}

type UnpaddedByteIndex uint64

type Verifier interface {
	VerifySeal(abi.SealVerifyInfo) (bool, error)
	VerifyElectionPost(ctx context.Context, info abi.PoStVerifyInfo) (bool, error)
	VerifyFallbackPost(ctx context.Context, info abi.PoStVerifyInfo) (bool, error)
}

type SectorPaths struct {
	Id abi.SectorID

	Unsealed string
	Sealed   string
	Cache    string
}

// Interfaces consumed by this package

type SectorProvider interface {
	AcquireSectorNumber() (abi.SectorNumber, error)

	FinalizeSector(abi.SectorNumber) error // move to long-term storage
	AcquireSector(id abi.SectorNumber, existing SectorFileType, allocate SectorFileType, sealing bool) (SectorPaths, func(), error)
}
