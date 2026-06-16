package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

type KeygenRequest struct {
	PartyID   string   `json:"party_id"`
	Peers     []string `json:"peers"`
	Threshold int      `json:"threshold"`
}

type SignRequest struct {
	PartyID string `json:"party_id"`
	Message string `json:"message"` // hex-encoded 32-byte message hash
}

var (
	savedData     keygen.LocalPartySaveData
	savedParams   *tss.Parameters
	savedPartyIDs []*tss.PartyID
)

func KeygenHandler(w http.ResponseWriter, r *http.Request) {
	var req KeygenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Peers) < req.Threshold+1 {
		http.Error(w, "number of peers must be >= threshold + 1", http.StatusBadRequest)
		return
	}

	partyIDs := make([]*tss.PartyID, 0, len(req.Peers))
	for _, pid := range req.Peers {
		partyIDs = append(partyIDs, tss.NewPartyID(pid, "", nil))
	}
	tss.SortPartyIDs(partyIDs)

	self := tss.NewPartyID(req.PartyID, "", nil)
	ctx := tss.NewPeerContext(partyIDs)

	params := tss.NewParameters(tss.S256(), ctx, self, len(partyIDs), req.Threshold)

	preParams, err := keygen.GeneratePreParams(5 * time.Minute)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to generate pre-params: %v", err), http.StatusInternalServerError)
		return
	}

	outCh := make(chan tss.Message, len(req.Peers)*4) // generous buffer to avoid deadlocks in tests
	endCh := make(chan keygen.LocalPartySaveData, 1)  // value, not pointer

	// Fix: dereference the pointer → pass value to variadic arg
	party := keygen.NewLocalParty(params, outCh, endCh, *preParams)

	// Alternative (if you still get errors or prefer slower but no pre-params hassle):
	// party := keygen.NewLocalParty(params, outCh, endCh) // library generates pre-params internally

	go func() {
		if err := party.Start(); err != nil {
			log.Printf("keygen.Start failed: %v", err)
		}
	}()

	select {
	case save := <-endCh:
		savedData = save
		savedParams = params
		savedPartyIDs = append([]*tss.PartyID(nil), partyIDs...) // safe copy
		json.NewEncoder(w).Encode(map[string]string{
			"status": "keygen complete",
			"party":  req.PartyID,
		})
	case <-time.After(4 * time.Minute):
		http.Error(w, "keygen timeout (likely because no message routing)", http.StatusGatewayTimeout)
	}
}

func SignHandler(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if savedParams == nil || savedData.Xi == nil {
		http.Error(w, "no valid key material available - run /keygen first", http.StatusBadRequest)
		return
	}

	msg := new(big.Int)
	if _, ok := msg.SetString(req.Message, 16); !ok || msg.BitLen() > 256 {
		http.Error(w, "invalid hex message (expected 32-byte hash)", http.StatusBadRequest)
		return
	}

	ctx := tss.NewPeerContext(savedPartyIDs)
	self := tss.NewPartyID(req.PartyID, "", nil)

	params := tss.NewParameters(tss.S256(), ctx, self, len(savedPartyIDs), savedParams.Threshold())

	outCh := make(chan tss.Message, 30)
	endCh := make(chan common.SignatureData, 1) // value type (non-pointer)

	party := signing.NewLocalParty(msg, params, savedData, outCh, endCh)
	go func() {
		if err := party.Start(); err != nil {
			log.Printf("sign.Start failed: %v", err)
		}
	}()

	select {
	case sig := <-endCh:
		json.NewEncoder(w).Encode(map[string]string{
			"R":         hex.EncodeToString(sig.R),
			"S":         hex.EncodeToString(sig.S),
			"Signature": hex.EncodeToString(sig.Signature),
			"Recovery":  fmt.Sprintf("%d", sig.Signature[64]), // usually the recovery byte (v)
		})
	case <-time.After(90 * time.Second):
		http.Error(w, "signing timeout (likely no message routing)", http.StatusGatewayTimeout)
	}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/keygen", KeygenHandler).Methods("POST")
	r.HandleFunc("/sign", SignHandler).Methods("POST")

	log.Println("TSS Wrapper running on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}