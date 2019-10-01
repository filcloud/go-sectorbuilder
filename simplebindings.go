package go_sectorbuilder

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/filecoin-project/go-sectorbuilder/sealing_state"
)

// #cgo LDFLAGS: ${SRCDIR}/libsector_builder_ffi.a
// #cgo pkg-config: ${SRCDIR}/sector_builder_ffi.pc
// #include "./sector_builder_ffi.h"
// #include <string.h>
import "C"

type SimpleStagedSectorMetadata struct {
	SectorID uint64
	Pieces   []PieceMetadata
	State    sealing_state.State
}

type PoStMetadata struct {
	ReqCid    string
	Proof     []byte
	CreatedAt time.Time
}

func InitSimpleSectorBuilder(
	sectorSize uint64,
	poRepProofPartitions uint8,
	poStProofPartitions uint8,
	sealedSectorDir string,
	stagedSectorDir string,
	maxNumOpenStagedSectors uint8,
) (unsafe.Pointer, error) {
	defer elapsed("InitSimpleSectorBuilder")()

	cStagedSectorDir := C.CString(stagedSectorDir)
	defer C.free(unsafe.Pointer(cStagedSectorDir))

	cSealedSectorDir := C.CString(sealedSectorDir)
	defer C.free(unsafe.Pointer(cSealedSectorDir))

	class, err := cSectorClass(sectorSize, poRepProofPartitions)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get sector class")
	}

	resPtr := C.sector_builder_ffi_init_simple_sector_builder(
		class,
		cSealedSectorDir,
		cStagedSectorDir,
		C.uint8_t(maxNumOpenStagedSectors),
	)
	defer C.sector_builder_ffi_destroy_init_simple_sector_builder_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	return unsafe.Pointer(resPtr.sector_builder), nil
}

func DestroySimpleSectorBuilder(sectorBuilderPtr unsafe.Pointer) {
	defer elapsed("DestroySectorBuilder")()

	C.sector_builder_ffi_destroy_simple_sector_builder((*C.sector_builder_ffi_SimpleSectorBuilder)(sectorBuilderPtr))
}

func AddPieceFirst(
	sectorBuilderPtr unsafe.Pointer,
	stagedSectorMetadata []SimpleStagedSectorMetadata,
	pieceBytes uint64,
	newSectorID uint64,
) {
	defer elapsed("AddPieceFirst")()

	sectorsPtr, sectorsLen := cStagedSectorMetadata(stagedSectorMetadata)

	resPtr := C.sector_builder_ffi_add_piece_first(
		(*C.sector_builder_ffi_SimpleSectorBuilder)(sectorBuilderPtr),
		sectorsPtr,
		sectorsLen,
		C.uint64_t(pieceBytes),
		C.uint64_t(newSectorID),
	)
	defer C.sector_builder_ffi_destroy_add_piece_response(resPtr)
}

func cStagedSectorMetadata(stagedSectorMetadata []SimpleStagedSectorMetadata) (*C.sector_builder_ffi_FFIPendingStagedSectorMetadata, C.size_t) {
	result := (*[1 << 30]C.sector_builder_ffi_FFIPendingStagedSectorMetadata)(C.malloc(C.size_t(len(stagedSectorMetadata) * C.sizeof_sector_builder_ffi_FFIPendingStagedSectorMetadata)))
	// defer C.free(result)
	for i, m := range stagedSectorMetadata {
		pieces := (*[1 << 30]C.sector_builder_ffi_FFIPieceMetadata)(C.malloc(C.size_t(len(m.Pieces) * C.sizeof_sector_builder_ffi_FFIPieceMetadata)))
		// defer C.free(pieces)
		for i, p := range m.Pieces {
			commPCBytes := C.CBytes(p.CommP[:])
			pieceInclusionProofCBytes := C.CBytes(p.InclusionProof)
			// defer C.free(pieceInclusionProofCBytes)
			pieces[i].piece_key = C.CString(p.Key)
			// defer C.free(unsafe.Pointer(pieces[i].piece_key))
			pieces[i].num_bytes = C.uint64_t(p.Size)
			C.memcpy(unsafe.Pointer(&pieces[i].comm_p[0]), commPCBytes, C.size_t(CommitmentBytesLen))
			C.free(commPCBytes)
			pieces[i].piece_inclusion_proof_ptr = (*C.uint8_t)(pieceInclusionProofCBytes)
			pieces[i].piece_inclusion_proof_len = C.size_t(len(p.InclusionProof))
		}

		cSectorAccess := C.CString(sectorKey(m.SectorID))
		// defer C.free(unsafe.Pointer(cSectorAccess))

		result[i].sector_access = cSectorAccess
		result[i].sector_id = C.uint64_t(m.SectorID)
		result[i].pieces_len = C.size_t(len(pieces))
		result[i].pieces_ptr = (*C.sector_builder_ffi_FFIPieceMetadata)(&pieces[0])
	}
	return &result[0], C.size_t(len(result))
}

func sectorKey(sectorID uint64) string {
	return fmt.Sprintf("on-000000000000-%010d", sectorID)
}
