package go_sectorbuilder

import (
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/pkg/errors"

	"github.com/filecoin-project/go-sectorbuilder/sealing_state"
)

// #cgo LDFLAGS: ${SRCDIR}/libsector_builder_ffi.a
// #cgo pkg-config: ${SRCDIR}/sector_builder_ffi.pc
// #include "./sector_builder_ffi.h"
import "C"

type SimpleStagedSectorMetadata struct {
	SectorID  uint64
	Pieces    []PieceMetadata
	State     sealing_state.State
	UpdatedAt time.Time
}

type MemCollector struct {
	ptrs []unsafe.Pointer
}

func (c *MemCollector) AddPtr(ptr unsafe.Pointer) {
	c.ptrs = append(c.ptrs, ptr)
}

func (c *MemCollector) Free() {
	for i := len(c.ptrs) - 1; i >= 0; i-- {
		C.free(c.ptrs[i])
	}
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
	miner string,
	stagedSectorMetadata []SimpleStagedSectorMetadata,
	pieceBytes uint64,
	newSectorID uint64,
) (uint64, error) {
	defer elapsed("AddPieceFirst")()

	c := new(MemCollector)
	defer c.Free()

	cMiner := C.CString(miner)
	defer C.free(unsafe.Pointer(cMiner))

	sectorsPtr, sectorsLen := cStagedSectorMetadata(c, stagedSectorMetadata)

	resPtr := C.sector_builder_ffi_add_piece_first(
		(*C.sector_builder_ffi_SimpleSectorBuilder)(sectorBuilderPtr),
		cMiner,
		sectorsPtr,
		sectorsLen,
		C.uint64_t(pieceBytes),
		C.uint64_t(newSectorID),
	)
	defer C.sector_builder_ffi_destroy_add_piece_response(resPtr)

	if resPtr.status_code != 0 {
		return 0, errors.New(C.GoString(resPtr.error_msg))
	}

	return uint64(resPtr.sector_id), nil
}

func AddPieceSecond(
	sectorBuilderPtr unsafe.Pointer,
	miner string,
	stagedSectorMetadata SimpleStagedSectorMetadata,
	pieceKey string,
	pieceBytes uint64,
	piecePath string,
) (SimpleStagedSectorMetadata, error) {
	defer elapsed("AddPieceSecond")()

	c := new(MemCollector)
	defer c.Free()

	cMiner := C.CString(miner)
	defer C.free(unsafe.Pointer(cMiner))

	cPieceKey := C.CString(pieceKey)
	defer C.free(unsafe.Pointer(cPieceKey))

	pieceFile, err := os.Open(piecePath)
	if err != nil {
		return SimpleStagedSectorMetadata{}, err
	}
	defer pieceFile.Close()
	pieceFd := pieceFile.Fd()

	sectorPtr, _ := cStagedSectorMetadata(c, []SimpleStagedSectorMetadata{stagedSectorMetadata})

	resPtr := C.sector_builder_ffi_add_piece_second(
		(*C.sector_builder_ffi_SimpleSectorBuilder)(sectorBuilderPtr),
		cMiner,
		sectorPtr,
		cPieceKey,
		C.int(pieceFd),
		C.uint64_t(pieceBytes),
	)
	defer C.sector_builder_ffi_destroy_add_piece_second_response(resPtr)

	runtime.KeepAlive(pieceFile)

	if resPtr.status_code != 0 {
		return SimpleStagedSectorMetadata{}, errors.New(C.GoString(resPtr.error_msg))
	}

	sectors, err := goPendingStagedSectorMetadata(resPtr.sector_ptr, resPtr.sector_len)
	if err != nil {
		return SimpleStagedSectorMetadata{}, err
	}

	return sectors[0], nil
}

func ReadPieceFromSpecifiedSealedSector(
	sectorBuilderPtr unsafe.Pointer,
	miner string,
	sealedSectorMetadata SealedSectorMetadata,
	pieceKey string,
	proverID [32]byte,
) ([]byte, error) {
	defer elapsed("ReadPieceFromSpecifiedSealedSector")()

	c := new(MemCollector)
	defer c.Free()

	cMiner := C.CString(miner)
	defer C.free(unsafe.Pointer(cMiner))

	cPieceKey := C.CString(pieceKey)
	defer C.free(unsafe.Pointer(cPieceKey))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	sectorPtr, _ := cSealedSectorMetadata(c, []SealedSectorMetadata{sealedSectorMetadata})

	resPtr := C.sector_builder_ffi_read_piece_from_specified_sealed_sector(
		(*C.sector_builder_ffi_SimpleSectorBuilder)(sectorBuilderPtr),
		cMiner,
		sectorPtr,
		cPieceKey,
		(*[32]C.uint8_t)(proverIDCBytes),
	)
	defer C.sector_builder_ffi_destroy_read_piece_from_specified_sealed_sector_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	return goBytes(resPtr.data_ptr, resPtr.data_len), nil
}

func SealStagedSector(
	sectorBuilderPtr unsafe.Pointer,
	miner string,
	stagedSectorMetadata SimpleStagedSectorMetadata,
	proverID [32]byte,
	ticket SealTicket,
) (SealedSectorMetadata, error) {
	defer elapsed("SealStagedSector")()

	c := new(MemCollector)
	defer c.Free()

	cMiner := C.CString(miner)
	defer C.free(unsafe.Pointer(cMiner))

	proverIDCBytes := C.CBytes(proverID[:])
	defer C.free(proverIDCBytes)

	cTicketBytes := C.CBytes(ticket.TicketBytes[:])
	defer C.free(cTicketBytes)

	cSealTicket := C.sector_builder_ffi_FFISealTicket{
		block_height: C.uint64_t(ticket.BlockHeight),
		ticket_bytes: *(*[32]C.uint8_t)(cTicketBytes),
	}

	sectorPtr, _ := cStagedSectorMetadata(c, []SimpleStagedSectorMetadata{stagedSectorMetadata})

	resPtr := C.sector_builder_ffi_seal_staged_sector(
		(*C.sector_builder_ffi_SimpleSectorBuilder)(sectorBuilderPtr),
		cMiner,
		sectorPtr,
		(*[32]C.uint8_t)(proverIDCBytes),
		cSealTicket,
	)
	defer C.sector_builder_ffi_destroy_seal_staged_sector_response(resPtr)

	if resPtr.status_code != 0 {
		return SealedSectorMetadata{}, errors.New(C.GoString(resPtr.error_msg))
	}

	sectors, err := goSealedSectorMetadata(resPtr.sector_ptr, resPtr.sector_len)
	if err != nil {
		return SealedSectorMetadata{}, err
	}

	return sectors[0], nil
}

type PoStChallenge struct {
	Sector uint64
	Leaf   uint64
}

func GeneratePoStFirst(
	sectorBuilderPtr unsafe.Pointer,
	challengeSeed [CommitmentBytesLen]byte,
	faults []uint64,
	sealedSectorMetadata []SealedSectorMetadata,
) ([]PoStChallenge, error) {
	defer elapsed("GeneratePoStFirst")()

	c := new(MemCollector)
	defer c.Free()

	challengeSeedPtr := unsafe.Pointer(&(challengeSeed)[0])

	faultsPtr, faultsSize := cUint64s(faults)
	defer C.free(unsafe.Pointer(faultsPtr))

	sectorsPtr, sectorsLen := cSealedSectorMetadata(c, sealedSectorMetadata)

	resPtr := C.sector_builder_ffi_generate_post_first(
		(*C.sector_builder_ffi_SimpleSectorBuilder)(sectorBuilderPtr),
		(*[CommitmentBytesLen]C.uint8_t)(challengeSeedPtr),
		faultsPtr,
		faultsSize,
		sectorsPtr,
		sectorsLen,
	)
	defer C.sector_builder_ffi_destroy_generate_post_first_response(resPtr)

	if resPtr.status_code != 0 {
		C.sector_builder_ffi_destroy_generate_post_first_response(resPtr)
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	return goChallengesSectors(resPtr.challenges_ptr, resPtr.challenges_len), nil
}

func GeneratePoStSecond(
	sectorBuilderPtr unsafe.Pointer,
	miner string,
	challenges []PoStChallenge,
	faults []uint64,
	sealedSectorMetadata []SealedSectorMetadata,
) ([]byte, error) {
	defer elapsed("GeneratePoStSecond")()

	c := new(MemCollector)
	defer c.Free()

	cMiner := C.CString(miner)
	defer C.free(unsafe.Pointer(cMiner))

	faultsPtr, faultsSize := cUint64s(faults)
	defer C.free(unsafe.Pointer(faultsPtr))

	challengesPtr, challengesLen := cChallengesSectors(c, challenges)

	sectorsPtr, sectorsLen := cSealedSectorMetadata(c, sealedSectorMetadata)

	resPtr := C.sector_builder_ffi_generate_post_second(
		(*C.sector_builder_ffi_SimpleSectorBuilder)(sectorBuilderPtr),
		cMiner,
		challengesPtr,
		challengesLen,
		faultsPtr,
		faultsSize,
		sectorsPtr,
		sectorsLen,
	)
	defer C.sector_builder_ffi_destroy_generate_post_second_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	return goBytes(resPtr.proof_ptr, resPtr.proof_len), nil
}

func GetSectorsReadyForSealing(
	sectorBuilderPtr unsafe.Pointer,
	stagedSectorMetadata []SimpleStagedSectorMetadata,
	sealAllStagedSectors bool,
) ([]uint64, error) {
	defer elapsed("GetSectorsReadyForSealing")()

	c := new(MemCollector)
	defer c.Free()

	sectorsPtr, sectorsLen := cStagedSectorMetadata(c, stagedSectorMetadata)

	resPtr := C.sector_builder_ffi_get_sectors_ready_for_sealing(
		(*C.sector_builder_ffi_SimpleSectorBuilder)(sectorBuilderPtr),
		sectorsPtr,
		sectorsLen,
		C.bool(sealAllStagedSectors),
	)
	defer C.sector_builder_ffi_destroy_get_sectors_ready_for_sealing_response(resPtr)

	if resPtr.status_code != 0 {
		return nil, errors.New(C.GoString(resPtr.error_msg))
	}

	var sectors []uint64
	if resPtr.sector_ids_len > 0 {
		cSectors := (*[1 << 30]C.uint64_t)(unsafe.Pointer(resPtr.sector_ids_ptr))[:resPtr.sector_ids_len:resPtr.sector_ids_len]
		for i := uint64(0); i < uint64(resPtr.sector_ids_len); i++ {
			sectors = append(sectors, uint64(cSectors[i]))
		}
	}

	return sectors, nil
}

func cStagedSectorMetadata(c *MemCollector, stagedSectorMetadata []SimpleStagedSectorMetadata) (*C.sector_builder_ffi_FFIPendingStagedSectorMetadata, C.size_t) {
	result := (*[1 << 30]C.sector_builder_ffi_FFIPendingStagedSectorMetadata)(C.malloc(C.size_t(len(stagedSectorMetadata) * C.sizeof_sector_builder_ffi_FFIPendingStagedSectorMetadata)))
	c.AddPtr(unsafe.Pointer(result))
	for i, m := range stagedSectorMetadata {
		piecesPtr, piecesLen := cPieceMetadata(c, m.Pieces)

		cSectorAccess := C.CString(sectorKey(m.SectorID))
		c.AddPtr(unsafe.Pointer(cSectorAccess))

		result[i].sector_access = cSectorAccess
		result[i].sector_id = C.uint64_t(m.SectorID)
		result[i].pieces_len = piecesLen
		result[i].pieces_ptr = piecesPtr
	}
	return &result[0], C.size_t(len(stagedSectorMetadata))
}

func cSealedSectorMetadata(c *MemCollector, sealedSectorMetadata []SealedSectorMetadata) (*C.sector_builder_ffi_FFISealedSectorMetadata, C.size_t) {
	result := (*[1 << 30]C.sector_builder_ffi_FFISealedSectorMetadata)(C.malloc(C.size_t(len(sealedSectorMetadata) * C.sizeof_sector_builder_ffi_FFISealedSectorMetadata)))
	c.AddPtr(unsafe.Pointer(result))
	for i, m := range sealedSectorMetadata {
		piecesPtr, piecesLen := cPieceMetadata(c, m.Pieces)

		cCopyArray(&result[i].comm_d[0], m.CommD[:])
		cCopyArray(&result[i].comm_r[0], m.CommR[:])
		result[i].pieces_len = piecesLen
		result[i].pieces_ptr = piecesPtr
		proofCBytes := C.CBytes(m.Proof)
		c.AddPtr(unsafe.Pointer(proofCBytes))
		result[i].proofs_len = C.size_t(len(m.Proof))
		result[i].proofs_ptr = (*C.uint8_t)(proofCBytes)
		cSectorAccess := C.CString(sectorKey(m.SectorID))
		c.AddPtr(unsafe.Pointer(cSectorAccess))
		result[i].sector_access = cSectorAccess
		result[i].sector_id = C.uint64_t(m.SectorID)
		result[i].health = C.Unknown

		result[i].seal_ticket.block_height = C.uint64_t(m.Ticket.BlockHeight)
		cCopyArray(&result[i].seal_ticket.ticket_bytes[0], m.Ticket.TicketBytes[:])

		commCCBytes := C.CBytes(m.PAux.CommC[:])
		commRLastCBytes := C.CBytes(m.PAux.CommRLast[:])
		c.AddPtr(unsafe.Pointer(commCCBytes))
		c.AddPtr(unsafe.Pointer(commRLastCBytes))
		result[i].p_aux.comm_c_len = C.size_t(len(m.PAux.CommC[:]))
		result[i].p_aux.comm_c_ptr = (*C.uint8_t)(commCCBytes)
		result[i].p_aux.comm_r_last_len = C.size_t(len(m.PAux.CommRLast[:]))
		result[i].p_aux.comm_r_last_ptr = (*C.uint8_t)(commRLastCBytes)
	}
	return &result[0], C.size_t(len(sealedSectorMetadata))
}

func cPieceMetadata(c *MemCollector, pieces []PieceMetadata) (*C.sector_builder_ffi_FFIPieceMetadata, C.size_t) {
	length := C.size_t(len(pieces))
	result := (*[1 << 30]C.sector_builder_ffi_FFIPieceMetadata)(C.malloc(length * C.sizeof_sector_builder_ffi_FFIPieceMetadata))
	c.AddPtr(unsafe.Pointer(result))
	for i, p := range pieces {
		result[i].piece_key = C.CString(p.Key)
		c.AddPtr(unsafe.Pointer(result[i].piece_key))
		result[i].num_bytes = C.uint64_t(p.Size)
		cCopyArray(&result[i].comm_p[0], p.CommP[:])
		pieceInclusionProofCBytes := C.CBytes(p.InclusionProof)
		c.AddPtr(unsafe.Pointer(pieceInclusionProofCBytes))
		result[i].piece_inclusion_proof_ptr = (*C.uint8_t)(pieceInclusionProofCBytes)
		result[i].piece_inclusion_proof_len = C.size_t(len(p.InclusionProof))
	}
	return &result[0], length
}

func goPendingStagedSectorMetadata(src *C.sector_builder_ffi_FFIPendingStagedSectorMetadata, size C.size_t) ([]SimpleStagedSectorMetadata, error) {
	if src == nil || size == 0 {
		return nil, nil
	}

	sectors := make([]SimpleStagedSectorMetadata, size)
	sectorPtrs := (*[1 << 30]C.sector_builder_ffi_FFIPendingStagedSectorMetadata)(unsafe.Pointer(src))[:size:size]
	for i := uint64(0); i < uint64(size); i++ {
		pieces, err := goPieceMetadata(sectorPtrs[i].pieces_ptr, sectorPtrs[i].pieces_len)
		if err != nil {
			return nil, err
		}
		sectors[i] = SimpleStagedSectorMetadata{
			SectorID: uint64(sectorPtrs[i].sector_id),
			Pieces:   pieces,
			State:    sealing_state.Pending,
		}
	}

	return sectors, nil
}

func goChallengesSectors(src *C.sector_builder_ffi_FFIChallenge, size C.size_t) []PoStChallenge {
	if src == nil || size == 0 {
		return nil
	}

	challenges := make([]PoStChallenge, size)
	challengesPtr := (*[1 << 30]C.sector_builder_ffi_FFIChallenge)(unsafe.Pointer(src))[:size:size]
	for i := uint64(0); i < uint64(size); i++ {
		challenges[i] = PoStChallenge{
			Sector: uint64(challengesPtr[i].sector),
			Leaf:   uint64(challengesPtr[i].leaf),
		}
	}
	return challenges
}

func cChallengesSectors(c *MemCollector, challenges []PoStChallenge) (*C.sector_builder_ffi_FFIChallenge, C.size_t) {
	length := C.size_t(len(challenges))
	result := (*[1 << 30]C.sector_builder_ffi_FFIChallenge)(C.malloc(length * C.sizeof_sector_builder_ffi_FFIChallenge))
	c.AddPtr(unsafe.Pointer(result))
	for i, c := range challenges {
		result[i].sector = C.uint64_t(c.Sector)
		result[i].leaf = C.uint64_t(c.Leaf)
	}
	return &result[0], length
}

func cCopyArray(dst *C.uint8_t, src []byte) {
	copy((*[1 << 30]byte)(unsafe.Pointer(dst))[:], src)
}

func sectorKey(sectorID uint64) string {
	// TODO: final design?
	return fmt.Sprintf("on-000000000000-%010d", sectorID)
}
