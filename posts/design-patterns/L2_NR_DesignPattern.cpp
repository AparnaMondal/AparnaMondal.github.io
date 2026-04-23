/**
 * 3GPP 5G NR L2 — Spec-Compliant C++ Implementation
 *
 * References
 *   TS 38.348  — SDAP
 *   TS 38.323  — PDCP
 *   TS 38.322  — RLC
 *   TS 38.321  — MAC
 *   TS 38.214  — Physical layer procedures (HARQ RV sequence)
 *
 * Design patterns used
 *   Chain of Responsibility  — PDCP Tx pipeline (correct spec order)
 *   Strategy + Factory       — RLC modes (TM / UM-SN6 / UM-SN12 / AM-SN12 / AM-SN18)
 *   State Machine            — RLC AM entity lifecycle (Rel-16 suspend/resume)
 *   Observer                 — MAC scheduler → UE observers
 *   Command                  — HARQ process (gNB-signalled RV)
 *
 * Compile: g++ -std=c++17 -Wall -Wextra -o l2_nr l2_nr_compliant.cpp
 */

#include <iostream>
#include <memory>
#include <vector>
#include <deque>
#include <queue>
#include <array>
#include <unordered_map>
#include <algorithm>
#include <stdexcept>
#include <cstdint>
#include <cassert>
#include <string>
#include <numeric>

// ====================================================================
// §0  Common types
// ====================================================================

using byte_t  = uint8_t;
using bytes_t = std::vector<byte_t>;

enum class BearerType { SRB, DRB };
enum class CipherAlgo { NEA0, NEA1, NEA2, NEA3 }; // null / SNOW3G / AES-CTR / ZUC
enum class IntegAlgo  { NIA0, NIA1, NIA2, NIA3 }; // null / SNOW3G / AES-CMAC / ZUC

// ====================================================================
// §1  SDAP — Service Data Adaptation Protocol (TS 38.348)
//
// New in 5G NR (no LTE equivalent).  A single SDAP entity is
// configured per PDU Session.  Its job is:
//   Tx: QFI marking in the SDAP Data PDU header; map QoS flow → DRB
//   Rx: strip SDAP header; reflective QoS mapping if RQI=1
//
// Header format (§5.3 / §6.1):  UL data PDU header = [R|QFI(6)] 1 byte
//                                DL data PDU header = [RDI|RQI|QFI(6)] 1 byte
// ====================================================================

using QosFlowId = uint8_t;  // 6-bit QFI, TS 38.331 §6.3.2
using DrbId     = uint8_t;

struct SdapConfig {
    uint8_t pdu_session_id = 0;
    bool    default_drb    = false;
    bool    sdap_hdr_ul    = true;  // whether SDAP header present on UL
    bool    sdap_hdr_dl    = true;
};

struct SdapSdu { bytes_t data; QosFlowId qfi = 0; };
struct SdapPdu { bytes_t data; QosFlowId qfi = 0; bool rqi = false; };

class SdapEntity {
    SdapConfig cfg_;
    std::unordered_map<QosFlowId, DrbId> ul_map_; // QFI → DRB (reflective-updated)

public:
    explicit SdapEntity(SdapConfig cfg) : cfg_(std::move(cfg)) {}

    void add_qfi_mapping(QosFlowId qfi, DrbId drb) { ul_map_[qfi] = drb; }

    // Tx: prepend SDAP Data PDU header (§5.2)
    SdapPdu tx(const SdapSdu& sdu) {
        SdapPdu pdu;
        pdu.qfi = sdu.qfi;
        if (cfg_.sdap_hdr_ul) {
            // UL: [R(1)|QFI(6)] — bit 7 reserved
            pdu.data.push_back(uint8_t(sdu.qfi & 0x3F));
        }
        pdu.data.insert(pdu.data.end(), sdu.data.begin(), sdu.data.end());
        std::cout << "[SDAP-Tx] QFI=" << int(sdu.qfi)
                  << " PDU=" << pdu.data.size() << "B\n";
        return pdu;
    }

    // Rx: strip SDAP header, update reflective QoS map
    SdapSdu rx(bytes_t raw) {
        SdapSdu sdu;
        if (cfg_.sdap_hdr_dl && !raw.empty()) {
            bool rqi = (raw[0] >> 6) & 1;
            sdu.qfi  = raw[0] & 0x3F;
            sdu.data = bytes_t(raw.begin() + 1, raw.end());
            if (rqi) {
                std::cout << "[SDAP-Rx] RQI set — reflective QoS map QFI="
                          << int(sdu.qfi) << "\n";
            }
        } else {
            sdu.data = std::move(raw);
        }
        return sdu;
    }
};

// ====================================================================
// §2  PDCP — Packet Data Convergence Protocol (TS 38.323)
//
// Key compliance fixes vs. previous version:
//  1. COUNT = HFN || SN (32 bits).  SN size 12 or 18 bits (DRBs),
//     12 bits (SRBs).  Configured via pdcp-SN-Size in RRC.
//  2. Correct Tx order (§5.2.1):
//       assign COUNT → ROHC → build header → MAC-I → cipher → assemble
//  3. Integrity: MAC-I computed over PDCP header + plaintext payload.
//     SRBs: always protected.  DRBs: optional since Rel-16.
//  4. Ciphering input: plaintext payload (+ MAC-I appended for SRBs
//     before ciphering per §5.8).
//  5. Crypto algorithm stubs: NEA0=null, NEA2=AES-CTR stub,
//     NIA0=null, NIA2=AES-CMAC stub.
// ====================================================================

// SN size (pdcp-SN-Size in TS 38.331 §6.3.2)
enum class PdcpSnSize : uint32_t { SN12 = 12, SN18 = 18 };

// COUNT = [HFN | SN] packed into 32 bits (§7.1)
class PdcpCount {
    uint32_t val_ = 0;
public:
    uint32_t raw()                              const { return val_; }
    uint32_t sn (PdcpSnSize sz)                const { return val_ & sn_mask(sz); }
    uint32_t hfn(PdcpSnSize sz)                const { return val_ >> uint32_t(sz); }
    void     advance()                               { ++val_; }

    static uint32_t sn_mask(PdcpSnSize sz) {
        return (1u << uint32_t(sz)) - 1u;
    }
};

// ---- Crypto stubs ----
// Real implementations: NEA2 = AES-128-CTR, NIA2 = AES-128-CMAC
// Inputs per spec: KEY(128b), COUNT(32b), BEARER(5b), DIRECTION(1b), LENGTH(32b), DATA

bytes_t nea_cipher(CipherAlgo algo, const bytes_t& key,
                   uint32_t count, uint8_t bearer, uint8_t dir, bytes_t data) {
    if (algo == CipherAlgo::NEA0) return data;          // null cipher
    // NEA2 stub: keystream XOR (NOT real AES-CTR)
    uint8_t ks = uint8_t(count) ^ uint8_t(count >> 8) ^ bearer ^ dir ^ key[0];
    for (auto& b : data) b ^= ks;
    return data;
}

uint32_t nia_mac_i(IntegAlgo algo, const bytes_t& key,
                   uint32_t count, uint8_t bearer, uint8_t dir,
                   const bytes_t& msg) {
    if (algo == IntegAlgo::NIA0) return 0;              // null integrity
    // NIA2 stub: accumulate XOR (NOT real AES-CMAC)
    uint32_t acc = count ^ uint32_t(bearer) ^ uint32_t(dir) ^ uint32_t(key[0]);
    for (auto b : msg) acc = ((acc << 3) | (acc >> 29)) ^ b;
    return acc;
}

// ---- PDCP configuration ----
struct PdcpConfig {
    BearerType bearer_type   = BearerType::DRB;
    PdcpSnSize sn_size       = PdcpSnSize::SN12;
    CipherAlgo cipher_algo   = CipherAlgo::NEA2;
    IntegAlgo  integ_algo    = IntegAlgo::NIA0;
    bool       integ_on_drb  = false;    // Rel-16: optional integrity on DRBs
    uint8_t    bearer_id     = 0;
    uint8_t    direction     = 0;        // 0=uplink, 1=downlink
    bytes_t    cipher_key    = bytes_t(16, 0xAB);
    bytes_t    integ_key     = bytes_t(16, 0xCD);
};

struct PdcpSdu { bytes_t data; };
struct PdcpPdu { bytes_t data; uint32_t count = 0; };

// ---- PDCP Tx entity — correct processing order per §5.2.1 ----
class PdcpTxEntity {
    PdcpConfig cfg_;
    PdcpCount  tx_next_;    // TX_NEXT — next COUNT to assign

    // ROHC stub: compress IP headers (user-plane DRBs only)
    bytes_t rohc_compress(bytes_t payload) const {
        if (cfg_.bearer_type == BearerType::SRB) return payload;
        if (payload.size() > 8)
            payload.resize(payload.size() - 2); // 2-byte simulated saving
        return payload;
    }

    // Build PDCP Data PDU header with SN (§6.2.2.1)
    bytes_t build_header(uint32_t sn) const {
        bytes_t hdr;
        if (cfg_.sn_size == PdcpSnSize::SN12) {
            // [D/C(1)=1 | R(3) | SN[11:8](4)] [SN[7:0]]
            hdr.push_back(uint8_t(0x80 | ((sn >> 8) & 0x0F)));
            hdr.push_back(uint8_t(sn & 0xFF));
        } else {
            // SN18: [D/C(1)=1 | R(5) | SN[17:16](2)] [SN[15:8]] [SN[7:0]]
            hdr.push_back(uint8_t(0x80 | ((sn >> 16) & 0x03)));
            hdr.push_back(uint8_t((sn >> 8) & 0xFF));
            hdr.push_back(uint8_t(sn & 0xFF));
        }
        return hdr;
    }

public:
    explicit PdcpTxEntity(PdcpConfig cfg) : cfg_(std::move(cfg)) {}

    PdcpPdu tx(PdcpSdu sdu) {
        // Step 1: Assign COUNT and advance TX_NEXT (§5.2.1)
        PdcpCount cnt = tx_next_;
        tx_next_.advance();
        uint32_t sn = cnt.sn(cfg_.sn_size);

        // Step 2: ROHC compression
        bytes_t payload = rohc_compress(std::move(sdu.data));

        // Step 3: Build PDCP header (needed as MAC-I input)
        bytes_t hdr = build_header(sn);

        // Step 4: Integrity protection — MAC-I computed over (header || plaintext)
        // §5.9: MESSAGE = PDCP_header || PDCP_SDU
        bool do_integ = (cfg_.bearer_type == BearerType::SRB)
                     || (cfg_.bearer_type == BearerType::DRB && cfg_.integ_on_drb);
        uint32_t mac_i = 0;
        if (do_integ) {
            bytes_t msg = hdr;
            msg.insert(msg.end(), payload.begin(), payload.end());
            mac_i = nia_mac_i(cfg_.integ_algo, cfg_.integ_key,
                              cnt.raw(), cfg_.bearer_id, cfg_.direction, msg);
        }

        // Step 5: Ciphering (§5.8)
        // SRBs: cipher(payload || MAC-I) per §5.8
        // DRBs with integ: cipher(payload), append plaintext MAC-I
        bytes_t to_cipher = payload;
        if (cfg_.bearer_type == BearerType::SRB) {
            to_cipher.push_back(uint8_t(mac_i >> 24));
            to_cipher.push_back(uint8_t(mac_i >> 16));
            to_cipher.push_back(uint8_t(mac_i >>  8));
            to_cipher.push_back(uint8_t(mac_i      ));
        }
        bytes_t ciphered = nea_cipher(cfg_.cipher_algo, cfg_.cipher_key,
                                       cnt.raw(), cfg_.bearer_id,
                                       cfg_.direction, std::move(to_cipher));
        if (cfg_.bearer_type == BearerType::DRB && cfg_.integ_on_drb) {
            ciphered.push_back(uint8_t(mac_i >> 24));
            ciphered.push_back(uint8_t(mac_i >> 16));
            ciphered.push_back(uint8_t(mac_i >>  8));
            ciphered.push_back(uint8_t(mac_i      ));
        }

        // Step 6: Assemble PDU = header || ciphered_data
        PdcpPdu pdu;
        pdu.count = cnt.raw();
        pdu.data  = hdr;
        pdu.data.insert(pdu.data.end(), ciphered.begin(), ciphered.end());

        std::cout << "[PDCP-Tx] bearer=" << int(cfg_.bearer_id)
                  << (cfg_.bearer_type == BearerType::SRB ? "(SRB)" : "(DRB)")
                  << " SN=" << sn
                  << " COUNT=" << cnt.raw()
                  << " PDU=" << pdu.data.size() << "B"
                  << " cipher=" << (cfg_.cipher_algo == CipherAlgo::NEA0 ? "NEA0" : "NEA2")
                  << " integ=" << (do_integ ? "yes" : "no") << "\n";
        return pdu;
    }
};

// ====================================================================
// §3  RLC — Radio Link Control (TS 38.322)
//
// Key compliance fixes:
//  1. SN assigned per SDU, not per segment (§5.3.3.1)
//  2. SI field (2 bits): 00=complete 01=first 10=last 11=middle
//  3. SO field (16 bits): present in all non-first segments
//  4. AM PDU header: D/C | P | SI | SN [| SO] (§6.2.2.2)
//  5. UM PDU header: R | R | SI | SN [| SO]   (§6.2.2.3)
//  6. SN sizes: UM={6,12} bits; AM={12,18} bits (RRC-configured)
//  7. AM state variables: VT(A), VT(S), VT(MS), VR(R), VR(MR)
//  8. STATUS PDU: ACK_SN + optional NACK_SN list (§6.2.2.5)
//  9. AM window sizes: 2048 (SN12) / 131072 (SN18)
// ====================================================================

// SI field — Segmentation Information (§6.2.2.2, 2 bits)
enum class RlcSI : uint8_t {
    COMPLETE    = 0b00,   // complete SDU
    FIRST_SEG   = 0b01,   // first segment
    LAST_SEG    = 0b10,   // last segment
    MIDDLE_SEG  = 0b11    // middle segment
};

struct RlcPdu {
    bytes_t  data;
    uint32_t sn      = 0;
    bool     is_ctrl = false; // STATUS PDU vs data PDU
};

struct RlcSduBuf {
    bytes_t  data;
    uint32_t sn        = 0;
    size_t   tx_offset = 0; // bytes already segmented
};

// ---- Strategy interface ----
class RlcMode {
public:
    virtual ~RlcMode() = default;
    virtual std::vector<RlcPdu> build_pdus(uint16_t grant_bytes) = 0;
    virtual void                rx_pdu(const RlcPdu&)            = 0;
    virtual void                rx_status(const RlcPdu&)         {}
    virtual const char*         name()                     const = 0;
};

// ---- TM Mode (§4.3.1) — no segmentation, no header ----
class TmMode : public RlcMode {
    std::queue<bytes_t> tx_buf_;
public:
    const char* name() const override { return "TM"; }
    void push_sdu(bytes_t s) { tx_buf_.push(std::move(s)); }

    std::vector<RlcPdu> build_pdus(uint16_t /*grant*/) override {
        std::vector<RlcPdu> out;
        while (!tx_buf_.empty()) {
            RlcPdu p;
            p.data = std::move(tx_buf_.front());
            tx_buf_.pop();
            out.push_back(std::move(p));
        }
        return out;
    }
    void rx_pdu(const RlcPdu& p) override {
        std::cout << "[RLC-TM] Rx transparent " << p.data.size() << "B\n";
    }
};

// ---- UM Mode (§4.3.2) — SN per SDU, segmentation, no ARQ ----
class UmMode : public RlcMode {
public:
    enum class SnSize : uint32_t { SN6 = 6, SN12 = 12 };

private:
    SnSize               sn_size_;
    uint32_t             sn_max_;
    uint32_t             vt_us_ = 0;    // VT(US) — next SN to assign
    std::deque<RlcSduBuf> tx_buf_;

    // UMD PDU header (§6.2.2.3)
    // SN6:  [R(1)|R(1)|SI(2)|SN(4)] = 1 byte; SO(16) if not first
    //   note: only upper 4 bits of 6-bit SN fit — lower 2 overlap into data area
    //   simplified: encode full SN in 1 byte as [SI(2)|SN(6)]
    // SN12: [R(1)|R(1)|SI(2)|SN[11:8](4)] [SN[7:0](8)] = 2 bytes; SO(16) if not first
    bytes_t make_umd_header(uint32_t sn, RlcSI si, bool has_so, uint16_t so) const {
        bytes_t h;
        if (sn_size_ == SnSize::SN6) {
            // 1-byte: [R|R|SI1|SI0|SN5|SN4|SN3|SN2] + lower 2 bits implicit
            h.push_back(uint8_t((uint8_t(si) << 6) | (sn & 0x3F)));
        } else {
            // 2-byte: [R|R|SI1|SI0|SN[11:8]] [SN[7:0]]
            h.push_back(uint8_t((uint8_t(si) << 4) | ((sn >> 8) & 0x0F)));
            h.push_back(uint8_t(sn & 0xFF));
        }
        if (has_so) {
            h.push_back(uint8_t(so >> 8));
            h.push_back(uint8_t(so & 0xFF));
        }
        return h;
    }

    size_t fixed_hdr_size()  const { return (sn_size_ == SnSize::SN6) ? 1u : 2u; }

public:
    explicit UmMode(SnSize sz = SnSize::SN12)
        : sn_size_(sz), sn_max_(1u << uint32_t(sz)) {}

    const char* name() const override { return "UM"; }

    void push_sdu(bytes_t s) {
        RlcSduBuf buf;
        buf.sn   = vt_us_++;
        vt_us_  %= sn_max_;
        buf.data = std::move(s);
        tx_buf_.push_back(std::move(buf));
    }

    std::vector<RlcPdu> build_pdus(uint16_t grant) override {
        std::vector<RlcPdu> pdus;
        uint16_t rem = grant;

        while (!tx_buf_.empty() && rem > 0) {
            auto& sdu     = tx_buf_.front();
            bool  is_1st  = (sdu.tx_offset == 0);
            bool  has_so  = !is_1st;
            size_t hdr_sz = fixed_hdr_size() + (has_so ? 2u : 0u);

            if (rem <= uint16_t(hdr_sz)) break;
            uint16_t pay = uint16_t(std::min<size_t>(
                rem - hdr_sz, sdu.data.size() - sdu.tx_offset));
            bool is_last  = (sdu.tx_offset + pay >= sdu.data.size());

            RlcSI si = (is_1st && is_last) ? RlcSI::COMPLETE
                     : (is_1st)            ? RlcSI::FIRST_SEG
                     : (is_last)           ? RlcSI::LAST_SEG
                                           : RlcSI::MIDDLE_SEG;

            auto hdr = make_umd_header(sdu.sn, si, has_so, uint16_t(sdu.tx_offset));

            RlcPdu pdu;
            pdu.sn   = sdu.sn;
            pdu.data = hdr;
            pdu.data.insert(pdu.data.end(),
                sdu.data.begin() + sdu.tx_offset,
                sdu.data.begin() + sdu.tx_offset + pay);

            sdu.tx_offset += pay;
            rem           -= uint16_t(pdu.data.size());
            if (is_last) tx_buf_.pop_front();
            pdus.push_back(std::move(pdu));
        }
        std::cout << "[RLC-UM-SN" << uint32_t(sn_size_) << "] grant=" << grant
                  << " → " << pdus.size() << " PDU(s)\n";
        return pdus;
    }

    void rx_pdu(const RlcPdu& p) override {
        std::cout << "[RLC-UM] Rx SN=" << p.sn << " " << p.data.size() << "B\n";
    }
};

// ---- AM Mode (§4.3.3) — segmentation + ARQ ----
class AmMode : public RlcMode {
public:
    enum class SnSize : uint32_t { SN12 = 12, SN18 = 18 };

private:
    SnSize   sn_size_;
    uint32_t sn_max_;
    uint32_t win_size_;     // 2048 or 131072

    // Tx state variables (§7.1)
    uint32_t vt_a_  = 0;   // oldest unacknowledged SN
    uint32_t vt_s_  = 0;   // next SN to assign to new SDU
    uint32_t vt_ms_;        // vt_a + win_size (send window ceiling)

    // Retransmission buffer indexed by SN
    std::unordered_map<uint32_t, bytes_t> retx_buf_;
    std::deque<RlcSduBuf>                  tx_buf_;
    bool                                   poll_pending_ = false;

    // AMD PDU header (§6.2.2.2):
    // SN12: [D/C(1)|P(1)|SI(2)|SN[11:8](4)] [SN[7:0]]           = 2B
    //       + optional [SO[15:8]] [SO[7:0]]                       (non-1st segs)
    // SN18: [D/C(1)|P(1)|SI(2)|R(1)|R(1)|SN[17:16](2)]
    //       [SN[15:8]] [SN[7:0]]                                  = 3B
    //       + optional [SO[15:8]] [SO[7:0]]
    bytes_t make_amd_header(uint32_t sn, bool p, RlcSI si,
                             bool has_so, uint16_t so) const {
        bytes_t h;
        if (sn_size_ == SnSize::SN12) {
            h.push_back(uint8_t(0x80 | (p ? 0x40 : 0) | (uint8_t(si) << 4) | ((sn >> 8) & 0x0F)));
            h.push_back(uint8_t(sn & 0xFF));
        } else {
            h.push_back(uint8_t(0x80 | (p ? 0x40 : 0) | (uint8_t(si) << 4) | ((sn >> 16) & 0x03)));
            h.push_back(uint8_t((sn >> 8) & 0xFF));
            h.push_back(uint8_t(sn & 0xFF));
        }
        if (has_so) { h.push_back(uint8_t(so >> 8)); h.push_back(uint8_t(so & 0xFF)); }
        return h;
    }

    size_t fixed_hdr_size() const { return (sn_size_ == SnSize::SN12) ? 2u : 3u; }

    // Check whether SN is inside the send window [VT(A), VT(MS))
    bool in_window(uint32_t sn) const {
        if (vt_a_ <= vt_ms_)
            return sn >= vt_a_ && sn < vt_ms_;
        return sn >= vt_a_ || sn < vt_ms_;  // wrap-around
    }

public:
    // STATUS PDU builder (§6.2.2.5)
    // Simplified: [D/C=0|CPT(3)=000|ACK_SN] [E1|(NACK_SN E1 E2 E3)*]
    static bytes_t build_status(SnSize sz, uint32_t ack_sn,
                                 const std::vector<uint32_t>& nacks) {
        bytes_t pdu;
        if (sz == SnSize::SN12) {
            // 2-byte ACK_SN field: [CPT=000|ACK[11:8]] [ACK[7:0]|E1]
            pdu.push_back(uint8_t((ack_sn >> 8) & 0x0F));
            pdu.push_back(uint8_t((ack_sn & 0xFF) | (nacks.empty() ? 0 : 1)));
            for (size_t i = 0; i < nacks.size(); ++i) {
                bool more = (i + 1 < nacks.size());
                pdu.push_back(uint8_t((nacks[i] >> 4) & 0xFF));
                pdu.push_back(uint8_t(((nacks[i] & 0x0F) << 1) | (more ? 1 : 0)));
            }
        } else {
            // SN18 status (3-byte ACK)
            pdu.push_back(uint8_t((ack_sn >> 14) & 0x0F));
            pdu.push_back(uint8_t((ack_sn >>  6) & 0xFF));
            pdu.push_back(uint8_t(((ack_sn & 0x3F) << 2) | (nacks.empty() ? 0 : 2)));
        }
        return pdu;
    }

    explicit AmMode(SnSize sz = SnSize::SN12)
        : sn_size_(sz)
        , sn_max_(1u << uint32_t(sz))
        , win_size_((sz == SnSize::SN12) ? 2048u : 131072u)
        , vt_ms_(win_size_) {}

    const char* name() const override { return "AM"; }

    void push_sdu(bytes_t s) {
        if (vt_s_ == vt_ms_) { // send window full
            std::cout << "[RLC-AM] Tx window full — SDU dropped\n";
            return;
        }
        RlcSduBuf buf;
        buf.sn   = vt_s_++;
        vt_s_   %= sn_max_;
        vt_ms_   = (vt_a_ + win_size_) % sn_max_;
        buf.data = std::move(s);
        tx_buf_.push_back(std::move(buf));
    }

    std::vector<RlcPdu> build_pdus(uint16_t grant) override {
        std::vector<RlcPdu> pdus;
        uint16_t rem = grant;

        while (!tx_buf_.empty() && rem > 0) {
            auto& sdu     = tx_buf_.front();
            bool  is_1st  = (sdu.tx_offset == 0);
            bool  has_so  = !is_1st;
            size_t hdr_sz = fixed_hdr_size() + (has_so ? 2u : 0u);

            if (rem <= uint16_t(hdr_sz)) break;
            uint16_t pay = uint16_t(std::min<size_t>(
                rem - hdr_sz, sdu.data.size() - sdu.tx_offset));
            bool is_last  = (sdu.tx_offset + pay >= sdu.data.size());

            RlcSI si = (is_1st && is_last) ? RlcSI::COMPLETE
                     : (is_1st)            ? RlcSI::FIRST_SEG
                     : (is_last)           ? RlcSI::LAST_SEG
                                           : RlcSI::MIDDLE_SEG;

            // Poll bit: set on last segment of last SDU in window (simplified)
            bool p = poll_pending_ && is_last && tx_buf_.size() == 1;
            if (p) poll_pending_ = false;

            auto hdr = make_amd_header(sdu.sn, p, si, has_so, uint16_t(sdu.tx_offset));

            RlcPdu pdu;
            pdu.sn   = sdu.sn;
            pdu.data = hdr;
            pdu.data.insert(pdu.data.end(),
                sdu.data.begin() + sdu.tx_offset,
                sdu.data.begin() + sdu.tx_offset + pay);

            retx_buf_[sdu.sn] = pdu.data;   // keep for potential ARQ retx
            sdu.tx_offset += pay;
            rem           -= uint16_t(pdu.data.size());
            if (is_last) tx_buf_.pop_front();
            pdus.push_back(std::move(pdu));
        }

        std::cout << "[RLC-AM-SN" << uint32_t(sn_size_)
                  << "] grant=" << grant << " → " << pdus.size() << " PDU(s)"
                  << " VT(A)=" << vt_a_ << " VT(S)=" << vt_s_ << "\n";
        return pdus;
    }

    // Process received STATUS PDU — advance VT(A), flush acked retx buffer (§5.3.3.4)
    void rx_status(const RlcPdu& pdu) override {
        if (pdu.data.size() < 2) return;
        uint32_t ack_sn = 0;
        if (sn_size_ == SnSize::SN12) {
            ack_sn = ((uint32_t(pdu.data[0]) & 0x0F) << 8) | pdu.data[1];
        } else if (pdu.data.size() >= 3) {
            ack_sn = ((uint32_t(pdu.data[0]) & 0x0F) << 14)
                   | (uint32_t(pdu.data[1]) << 6)
                   | ((pdu.data[2] >> 2) & 0x3F);
        }
        std::cout << "[RLC-AM] STATUS: ACK_SN=" << ack_sn
                  << " (advancing VT(A) from " << vt_a_ << ")\n";
        while (vt_a_ != ack_sn) {
            retx_buf_.erase(vt_a_);
            vt_a_  = (vt_a_  + 1) % sn_max_;
            vt_ms_ = (vt_a_  + win_size_) % sn_max_;
        }
    }

    void rx_pdu(const RlcPdu& p) override {
        std::cout << "[RLC-AM] Rx AMD SN=" << p.sn << "\n";
    }

    void request_poll() { poll_pending_ = true; }
};

// ---- RLC entity wrapper (holds mode strategy) ----
class RlcEntity {
    std::unique_ptr<RlcMode> mode_;
    uint8_t                  bearer_id_;

    template<typename T> T* as() { return dynamic_cast<T*>(mode_.get()); }

public:
    RlcEntity(std::unique_ptr<RlcMode> m, uint8_t id)
        : mode_(std::move(m)), bearer_id_(id) {}

    void push_sdu(bytes_t s) {
        if (auto* p = as<TmMode>())      p->push_sdu(std::move(s));
        else if (auto* p = as<UmMode>()) p->push_sdu(std::move(s));
        else if (auto* p = as<AmMode>()) p->push_sdu(std::move(s));
    }

    std::vector<RlcPdu> build_pdus(uint16_t grant) { return mode_->build_pdus(grant); }

    void rx_pdu(const RlcPdu& p) {
        if (p.is_ctrl) mode_->rx_status(p);
        else           mode_->rx_pdu(p);
    }

    const char* mode_name() const { return mode_->name(); }
    uint8_t     bearer_id() const { return bearer_id_; }
};

// ---- Factory (Pattern 3) ----
enum class RlcModeType { TM, UM_SN6, UM_SN12, AM_SN12, AM_SN18 };

class RlcFactory {
public:
    static std::unique_ptr<RlcEntity> create(RlcModeType type, uint8_t bearer_id) {
        std::cout << "[RlcFactory] Creating "
                  << (type == RlcModeType::TM     ? "TM"
                    : type == RlcModeType::UM_SN6  ? "UM-SN6"
                    : type == RlcModeType::UM_SN12 ? "UM-SN12"
                    : type == RlcModeType::AM_SN12 ? "AM-SN12"
                                                   : "AM-SN18")
                  << " bearer=" << int(bearer_id) << "\n";
        switch (type) {
        case RlcModeType::TM:
            return std::make_unique<RlcEntity>(std::make_unique<TmMode>(), bearer_id);
        case RlcModeType::UM_SN6:
            return std::make_unique<RlcEntity>(
                std::make_unique<UmMode>(UmMode::SnSize::SN6), bearer_id);
        case RlcModeType::UM_SN12:
            return std::make_unique<RlcEntity>(
                std::make_unique<UmMode>(UmMode::SnSize::SN12), bearer_id);
        case RlcModeType::AM_SN12:
            return std::make_unique<RlcEntity>(
                std::make_unique<AmMode>(AmMode::SnSize::SN12), bearer_id);
        case RlcModeType::AM_SN18:
            return std::make_unique<RlcEntity>(
                std::make_unique<AmMode>(AmMode::SnSize::SN18), bearer_id);
        }
        throw std::invalid_argument("Unknown RLC mode");
    }
};

// ---- State machine — RLC AM entity lifecycle (TS 38.322 §5.1, Rel-16 suspend/resume) ----
enum class RlcAmState { IDLE, DATA_TRANSFER_READY, SUSPENDED };

class RlcAmStateMachine {
    RlcAmState state_ = RlcAmState::IDLE;

    static const char* str(RlcAmState s) {
        switch (s) {
        case RlcAmState::IDLE:                return "IDLE";
        case RlcAmState::DATA_TRANSFER_READY: return "DATA_TRANSFER_READY";
        case RlcAmState::SUSPENDED:           return "SUSPENDED";
        }
        return "?";
    }

    void go(RlcAmState next) {
        std::cout << "[RLC-AM-SM] " << str(state_) << " → " << str(next) << "\n";
        state_ = next;
    }

public:
    void on_establishment() {
        if (state_ != RlcAmState::IDLE) throw std::logic_error("Not IDLE");
        go(RlcAmState::DATA_TRANSFER_READY);
    }
    void on_suspend() { // Rel-16 RRC Suspend (§5.1.3.3)
        if (state_ != RlcAmState::DATA_TRANSFER_READY)
            throw std::logic_error("Not DATA_TRANSFER_READY");
        go(RlcAmState::SUSPENDED);
    }
    void on_resume() {  // Rel-16 RRC Resume
        if (state_ != RlcAmState::SUSPENDED) throw std::logic_error("Not SUSPENDED");
        go(RlcAmState::DATA_TRANSFER_READY);
    }
    void on_release() { go(RlcAmState::IDLE); }
    bool can_tx()    const { return state_ == RlcAmState::DATA_TRANSFER_READY; }
};

// ====================================================================
// §4  MAC — Medium Access Control (TS 38.321)
//
// Key compliance fixes:
//  1. LCG-based BSR (§5.4.3.1): logical channels grouped into LCGs (0..7).
//     Short BSR (LCID=62): 1 byte — [LCGID(3)|BufferSize(5)].
//     Long BSR  (LCID=60): variable — [bitmap(8)] + per-LCG BufferSize(5b each).
//  2. HARQ entity: max 16 UL + 16 DL processes (§5.3.1).
//  3. RV is signalled by gNB in DCI — UE must use the indicated RV.
//     Standard sequence: 0→2→3→1 per TS 38.214 Table 6.1.2.1-2.
//  4. MAC PDU multiplexing (§6.1.2): CEs first (ordered by LCID priority),
//     then data subPDUs.  SubPDU header: [R|F|LCID(6)] + L-field + payload.
//  5. Priority-ordered LCH serving (§5.4.3.1): serve higher-priority
//     LCHs first; within same priority, use PBR token bucket.
//  6. Round Robin scheduler with per-UE CQI-based TBS allocation.
// ====================================================================

// BSR buffer-size table (5-bit index, §6.1.3.1 Table 6.1.3.1-1, subset)
static const uint32_t kBsrTable[32] = {
      0,    10,    13,    17,    23,    31,    41,    55,
     74,    99,   133,   178,   238,   319,   426,   570,
    762,  1019,  1363,  1822,  2436,  3258,  4355,  5822,
   7786, 10411, 13921, 18614, 24893, 33268, 44478, 59449
};

static uint8_t bytes_to_bsr_idx(uint32_t bytes) {
    for (uint8_t i = 0; i < 32; ++i)
        if (kBsrTable[i] >= bytes) return i;
    return 31;
}

// MAC CE LCIDs (TS 38.321 Table 6.2.1-2, UL)
constexpr uint8_t LCID_LONG_BSR         = 60;
constexpr uint8_t LCID_LONG_TRUNC_BSR   = 59;
constexpr uint8_t LCID_SHORT_BSR        = 62;
constexpr uint8_t LCID_SHORT_TRUNC_BSR  = 61;
constexpr uint8_t LCID_PHR              = 57;   // Power Headroom Report

struct ShortBsr { uint8_t lcg_id; uint8_t bsr_idx; };
struct LongBsr  { uint8_t bitmap; std::vector<uint8_t> bsr_idxs; };

// Logical channel configuration (TS 38.321 §5.4.3.1)
struct LcConfig {
    uint8_t  lcid;
    uint8_t  lcg;          // LCG ID (0..7)
    uint8_t  priority;     // 1..16 (1=highest)
    uint32_t pbr_bytes;    // Prioritised Bit Rate (bytes/TTI); 0=infinity
    uint8_t  bsd_ttis;     // Bucket Size Duration (multiples of PBR)
};

class LogicalChannel {
    LcConfig cfg_;
    uint32_t pending_  = 0;
    int32_t  bucket_   = 0; // PBR token bucket
public:
    explicit LogicalChannel(LcConfig cfg) : cfg_(std::move(cfg)) {
        bucket_ = int32_t(cfg_.pbr_bytes) * cfg_.bsd_ttis;
    }
    void     push(uint32_t n) { pending_ += n; }
    uint32_t pending()  const { return pending_; }
    uint8_t  lcid()     const { return cfg_.lcid; }
    uint8_t  lcg()      const { return cfg_.lcg; }
    uint8_t  priority() const { return cfg_.priority; }
    uint32_t pbr()      const { return cfg_.pbr_bytes; }

    uint32_t serve(uint32_t grant) {
        uint32_t s = std::min(grant, pending_);
        pending_  -= s;
        bucket_   -= int32_t(s);
        return s;
    }
};

// MAC PDU MUX (§6.1.2): subPDU header = [R(1)|F(1)|LCID(6)] [L(8 or 16)] payload
class MacMux {
public:
    struct SubPdu { uint8_t lcid; bytes_t payload; };

    static bytes_t build(const std::vector<SubPdu>& subs) {
        bytes_t pdu;
        for (const auto& s : subs) {
            bool large = s.payload.size() > 255;
            pdu.push_back(uint8_t((s.lcid & 0x3F) | (large ? 0x40 : 0)));
            if (large) pdu.push_back(uint8_t(s.payload.size() >> 8));
            pdu.push_back(uint8_t(s.payload.size() & 0xFF));
            pdu.insert(pdu.end(), s.payload.begin(), s.payload.end());
        }
        return pdu;
    }
};

// ---- HARQ process — Command pattern ----
// RV sequence per TS 38.214 Table 6.1.2.1-2: initial Tx=0, retx: 2→3→1 (UL HARQ type-A)
static const uint8_t kRvSequence[4] = { 0, 2, 3, 1 };

class HarqProcess {
    uint8_t pid_      = 0xFF;
    uint8_t retx_cnt_ = 0;
    bool    active_   = false;
    bytes_t cached_tb_;
    static constexpr uint8_t MAX_RETX = 4;

public:
    HarqProcess() = default;
    void init(uint8_t pid) { pid_ = pid; }

    // New transmission (RV=0 always for initial Tx)
    void new_tx(bytes_t tb) {
        cached_tb_ = std::move(tb);
        retx_cnt_  = 0;
        active_    = true;
        std::cout << "[HARQ-" << int(pid_) << "] New Tx TBS="
                  << cached_tb_.size() << "B RV=0\n";
    }

    // Retransmission: gNB signals the exact RV in DCI (TS 38.214 §5.4.2.1)
    bool retx(uint8_t gNB_rv) {
        if (!active_) return false;
        if (retx_cnt_ >= MAX_RETX) {
            std::cout << "[HARQ-" << int(pid_) << "] Max retx reached — flush\n";
            flush();
            return false;
        }
        ++retx_cnt_;
        std::cout << "[HARQ-" << int(pid_) << "] Retx #" << int(retx_cnt_)
                  << " gNB-signalled RV=" << int(gNB_rv)
                  << " TBS=" << cached_tb_.size() << "B\n";
        return true;
    }

    void ack() {
        std::cout << "[HARQ-" << int(pid_) << "] ACK — process free\n";
        flush();
    }

    void flush() { active_ = false; retx_cnt_ = 0; cached_tb_.clear(); }
    bool is_active() const { return active_; }
    uint8_t pid()    const { return pid_; }
};

// ---- HARQ entity: 16 UL + 16 DL processes (TS 38.321 §5.3.1) ----
class HarqEntity {
    static constexpr uint8_t NUM_PROCS = 16;
    std::array<HarqProcess, NUM_PROCS> ul_;
    std::array<HarqProcess, NUM_PROCS> dl_;

public:
    HarqEntity() {
        for (uint8_t i = 0; i < NUM_PROCS; ++i) { ul_[i].init(i); dl_[i].init(i); }
    }

    uint8_t find_free_ul_pid() const {
        for (uint8_t i = 0; i < NUM_PROCS; ++i)
            if (!ul_[i].is_active()) return i;
        return 0xFF; // none free
    }

    void ul_new_tx(uint8_t pid, bytes_t tb) {
        if (pid < NUM_PROCS) ul_[pid].new_tx(std::move(tb));
    }
    void ul_retx(uint8_t pid, uint8_t rv) {
        if (pid < NUM_PROCS) ul_[pid].retx(rv);
    }
    void ul_ack(uint8_t pid) {
        if (pid < NUM_PROCS) ul_[pid].ack();
    }
    void dl_new_rx(uint8_t pid, bytes_t tb) {
        if (pid < NUM_PROCS) dl_[pid].new_tx(std::move(tb));
    }
    void dl_retx(uint8_t pid, uint8_t rv) {
        if (pid < NUM_PROCS) dl_[pid].retx(rv);
    }
    void dl_ack(uint8_t pid) {
        if (pid < NUM_PROCS) dl_[pid].ack();
    }
};

// ---- DCI grant structures ----
struct DciUlGrant {
    uint16_t rnti      = 0;
    uint32_t tbs_bytes = 0;
    uint8_t  harq_pid  = 0;
    uint8_t  rv        = 0;   // gNB-signalled RV
    bool     new_data  = true;
};

struct DciDlGrant {
    uint16_t rnti      = 0;
    uint32_t tbs_bytes = 0;
    uint8_t  harq_pid  = 0;
    uint8_t  rv        = 0;
    bool     new_data  = true;
};

// ---- Observer interface ----
class ISchedulerObserver {
public:
    virtual void on_ul_grant(const DciUlGrant&) = 0;
    virtual void on_dl_grant(const DciDlGrant&) = 0;
    virtual ~ISchedulerObserver() = default;
};

// ---- UE context tracked by scheduler ----
struct UeContext {
    uint16_t rnti      = 0;
    uint32_t ul_buf    = 0;   // bytes signalled via BSR
    uint32_t dl_buf    = 0;
    uint8_t  cqi       = 10;  // CQI 1..15; updated via UCI
};

// ====================================================================
// §4.1  MAC scheduler — Round Robin with per-UE CQI TBS allocation
//
// Observer pattern: scheduler is Subject; UE MAC entities are Observers.
// Per TS 38.321 §5.4: scheduler runs each TTI, issues DCI grants.
// RV for initial Tx = 0; RV for retx = as in TS 38.214 Table 6.1.2.1-2.
// ====================================================================
class MacScheduler {
    std::vector<ISchedulerObserver*> observers_;
    std::vector<UeContext>           ues_;
    size_t   ul_rr_ptr_ = 0;
    size_t   dl_rr_ptr_ = 0;
    uint8_t  harq_pid_  = 0;

    uint8_t next_pid() {
        uint8_t p = harq_pid_++;
        if (harq_pid_ >= 16) harq_pid_ = 0;
        return p;
    }

    // Simplified CQI → TBS: higher CQI ≈ higher spectral efficiency
    // Real: MCS table TS 38.214 §5.1.3.1; PDSCH/PUSCH capacity formula
    uint32_t tbs_from_cqi(uint8_t cqi, uint32_t max_bytes) const {
        uint32_t eff = uint32_t(std::max(uint8_t(1), cqi)) * 80u; // bytes/TTI per CQI level
        return std::min(eff, max_bytes);
    }

    void notify_ul(const DciUlGrant& g) {
        for (auto* o : observers_) o->on_ul_grant(g);
    }
    void notify_dl(const DciDlGrant& g) {
        for (auto* o : observers_) o->on_dl_grant(g);
    }

public:
    void subscribe(ISchedulerObserver* o)   { observers_.push_back(o); }
    void unsubscribe(ISchedulerObserver* o) {
        observers_.erase(std::remove(observers_.begin(), observers_.end(), o),
                         observers_.end());
    }

    void add_ue(UeContext ctx) { ues_.push_back(std::move(ctx)); }

    // Called when UE reports BSR
    void report_bsr(uint16_t rnti, uint32_t bytes) {
        for (auto& u : ues_)
            if (u.rnti == rnti) { u.ul_buf = bytes; break; }
    }

    void set_dl_buffer(uint16_t rnti, uint32_t bytes) {
        for (auto& u : ues_)
            if (u.rnti == rnti) { u.dl_buf = bytes; break; }
    }

    // Run one UL TTI — Round Robin over UEs with pending data (§5.4.3)
    void run_ul_tti(uint32_t cell_grant_bytes) {
        if (ues_.empty()) return;
        uint32_t rem   = cell_grant_bytes;
        size_t   start = ul_rr_ptr_;
        std::cout << "\n[Scheduler] === UL TTI: cell_grant=" << rem << "B ===\n";

        for (size_t i = 0; i < ues_.size() && rem > 0; ++i) {
            size_t idx = (start + i) % ues_.size();
            auto&  ue  = ues_[idx];
            if (ue.ul_buf == 0) continue;

            uint32_t grant = tbs_from_cqi(ue.cqi, std::min(rem, ue.ul_buf));
            if (grant == 0) continue;

            DciUlGrant dci;
            dci.rnti      = ue.rnti;
            dci.tbs_bytes = grant;
            dci.harq_pid  = next_pid();
            dci.rv        = kRvSequence[0]; // initial Tx always RV=0
            dci.new_data  = true;

            std::cout << "[Scheduler] UL grant RNTI=0x" << std::hex << ue.rnti << std::dec
                      << " TBS=" << grant << "B HARQ=" << int(dci.harq_pid)
                      << " RV=" << int(dci.rv) << " CQI=" << int(ue.cqi) << "\n";

            ue.ul_buf -= std::min(ue.ul_buf, grant);
            rem       -= grant;
            ul_rr_ptr_ = (idx + 1) % ues_.size();
            notify_ul(dci);
        }
    }

    // Run one DL TTI
    void run_dl_tti(uint32_t cell_grant_bytes) {
        if (ues_.empty()) return;
        uint32_t rem   = cell_grant_bytes;
        size_t   start = dl_rr_ptr_;
        std::cout << "\n[Scheduler] === DL TTI: cell_grant=" << rem << "B ===\n";

        for (size_t i = 0; i < ues_.size() && rem > 0; ++i) {
            size_t idx = (start + i) % ues_.size();
            auto&  ue  = ues_[idx];
            if (ue.dl_buf == 0) continue;

            uint32_t grant = tbs_from_cqi(ue.cqi, std::min(rem, ue.dl_buf));
            if (grant == 0) continue;

            DciDlGrant dci;
            dci.rnti      = ue.rnti;
            dci.tbs_bytes = grant;
            dci.harq_pid  = next_pid();
            dci.rv        = kRvSequence[0];
            dci.new_data  = true;

            std::cout << "[Scheduler] DL grant RNTI=0x" << std::hex << ue.rnti << std::dec
                      << " TBS=" << grant << "B HARQ=" << int(dci.harq_pid)
                      << " RV=" << int(dci.rv) << "\n";

            ue.dl_buf -= std::min(ue.dl_buf, grant);
            rem       -= grant;
            dl_rr_ptr_ = (idx + 1) % ues_.size();
            notify_dl(dci);
        }
    }

    // Issue HARQ retransmission DCI — gNB picks RV (TS 38.214 §5.4.2.1)
    void issue_ul_retx(uint16_t rnti, uint8_t pid, uint8_t retx_num) {
        uint8_t rv = kRvSequence[retx_num % 4];
        DciUlGrant dci;
        dci.rnti     = rnti;
        dci.harq_pid = pid;
        dci.rv       = rv;
        dci.new_data = false;
        std::cout << "[Scheduler] UL retx RNTI=0x" << std::hex << rnti << std::dec
                  << " HARQ=" << int(pid) << " RV=" << int(rv)
                  << " (retx#" << int(retx_num) << ")\n";
        notify_ul(dci);
    }
};

// ---- UE MAC entity — implements Observer ----
class MacUeEntity : public ISchedulerObserver {
    uint16_t                      rnti_;
    HarqEntity                    harq_;
    std::vector<LogicalChannel*>  lchs_;
    MacScheduler*                 sched_;

    // Build Short or Long BSR MAC CE (§5.4.3.1, §6.1.3.1)
    MacMux::SubPdu build_bsr_ce() {
        std::unordered_map<uint8_t, uint32_t> lcg_bytes;
        for (auto* lc : lchs_)
            if (lc->pending() > 0) lcg_bytes[lc->lcg()] += lc->pending();

        MacMux::SubPdu ce;
        if (lcg_bytes.size() <= 1) {
            // Short BSR (LCID=62): [LCGID(3)|BufferSize(5)] = 1 byte
            ce.lcid = LCID_SHORT_BSR;
            uint8_t lcg = lcg_bytes.empty() ? 0 : lcg_bytes.begin()->first;
            uint32_t b  = lcg_bytes.empty() ? 0 : lcg_bytes.begin()->second;
            ce.payload  = { uint8_t((lcg << 5) | (bytes_to_bsr_idx(b) & 0x1F)) };
            std::cout << "[MAC-UE:0x" << std::hex << rnti_ << std::dec
                      << "] Short BSR LCG=" << int(lcg)
                      << " idx=" << int(bytes_to_bsr_idx(b)) << "\n";
        } else {
            // Long BSR (LCID=60): [LCG_bitmap(8)] + per-LCG BufferSize(5b each)
            ce.lcid = LCID_LONG_BSR;
            uint8_t bmap = 0;
            for (auto& [lcg, _] : lcg_bytes) bmap |= (1u << lcg);
            ce.payload.push_back(bmap);
            for (auto& [lcg, bytes] : lcg_bytes)
                ce.payload.push_back(bytes_to_bsr_idx(bytes));
            std::cout << "[MAC-UE:0x" << std::hex << rnti_ << std::dec
                      << "] Long BSR bitmap=0x" << std::hex << int(bmap) << std::dec << "\n";
        }
        return ce;
    }

public:
    MacUeEntity(uint16_t rnti, MacScheduler* s) : rnti_(rnti), sched_(s) {
        sched_->subscribe(this);
    }
    ~MacUeEntity() { sched_->unsubscribe(this); }

    void add_lch(LogicalChannel* lc) { lchs_.push_back(lc); }

    // Called by scheduler observer notification
    void on_ul_grant(const DciUlGrant& dci) override {
        if (dci.rnti != rnti_) return;

        if (!dci.new_data) {
            // Retransmission: use gNB-signalled RV (NOT chosen by UE)
            harq_.ul_retx(dci.harq_pid, dci.rv);
            return;
        }

        std::cout << "[MAC-UE:0x" << std::hex << rnti_ << std::dec
                  << "] UL grant TBS=" << dci.tbs_bytes
                  << "B HARQ=" << int(dci.harq_pid) << "\n";

        // Priority-ordered LCH serving (§5.4.3.1): sort by priority (lower # = higher)
        auto sorted = lchs_;
        std::sort(sorted.begin(), sorted.end(),
                  [](auto* a, auto* b){ return a->priority() < b->priority(); });

        std::vector<MacMux::SubPdu> subs;

        // 1. BSR MAC CE (always first — CE before data per §6.1.2)
        auto bsr_ce = build_bsr_ce();
        uint32_t overhead = 2 + uint32_t(bsr_ce.payload.size()); // subPDU header + CE
        subs.push_back(std::move(bsr_ce));

        // 2. Optional PHR CE (Power Headroom, LCID=57) — stubbed once
        static bool phr_sent = false;
        if (!phr_sent) {
            MacMux::SubPdu phr;
            phr.lcid    = LCID_PHR;
            phr.payload = { 0x20 }; // PCmax - P_PUSCH stub
            overhead   += 2 + 1;
            subs.push_back(std::move(phr));
            phr_sent = true;
            std::cout << "[MAC-UE:0x" << std::hex << rnti_ << std::dec
                      << "] PHR CE included\n";
        }

        // 3. Data subPDUs — serve highest-priority LCHs first
        uint32_t rem = (dci.tbs_bytes > overhead) ? (dci.tbs_bytes - overhead) : 0;
        for (auto* lc : sorted) {
            if (rem == 0 || lc->pending() == 0) continue;
            uint32_t served = lc->serve(rem);
            if (served == 0) continue;
            MacMux::SubPdu data;
            data.lcid    = lc->lcid();
            data.payload = bytes_t(served, 0xDA);
            rem         -= std::min(rem, served + 2u);
            std::cout << "[MAC-UE:0x" << std::hex << rnti_ << std::dec
                      << "] LCH-" << int(lc->lcid()) << "(LCG=" << int(lc->lcg())
                      << ",prio=" << int(lc->priority()) << ") served=" << served << "B\n";
            subs.push_back(std::move(data));
        }

        // 4. Build MAC PDU and pass to HARQ
        auto mac_pdu = MacMux::build(subs);
        harq_.ul_new_tx(dci.harq_pid, std::move(mac_pdu));
    }

    void on_dl_grant(const DciDlGrant& dci) override {
        if (dci.rnti != rnti_) return;
        if (!dci.new_data) { harq_.dl_retx(dci.harq_pid, dci.rv); return; }
        std::cout << "[MAC-UE:0x" << std::hex << rnti_ << std::dec
                  << "] DL grant TBS=" << dci.tbs_bytes
                  << "B HARQ=" << int(dci.harq_pid) << "\n";
        harq_.dl_new_rx(dci.harq_pid, bytes_t(dci.tbs_bytes, 0xDD));
    }

    // Simulate receiving NACK feedback from gNB → retransmit
    void nack_ul(uint8_t pid, uint8_t retx_num) {
        uint8_t rv = kRvSequence[retx_num % 4];
        harq_.ul_retx(pid, rv);
    }
    void ack_ul(uint8_t pid) { harq_.ul_ack(pid); }
};

// ====================================================================
// §5  Main — end-to-end demonstration
// ====================================================================

int main() {
    std::cout << "=== 3GPP 5G NR L2 — Spec-Compliant Demo ===\n\n";

    // ----------------------------------------------------------------
    // 1. SDAP (TS 38.348) — QFI marking and DRB mapping
    // ----------------------------------------------------------------
    std::cout << "--- §1 SDAP (TS 38.348) ---\n";
    {
        SdapConfig sdap_cfg;
        sdap_cfg.pdu_session_id = 1;
        sdap_cfg.default_drb    = true;
        sdap_cfg.sdap_hdr_ul    = true;
        sdap_cfg.sdap_hdr_dl    = true;
        SdapEntity sdap(sdap_cfg);
        sdap.add_qfi_mapping(5, 1);
        sdap.add_qfi_mapping(9, 2);

        SdapSdu sdu;
        sdu.qfi  = 5;
        sdu.data = { 0x45, 0x00, 0x00, 0x3C }; // IPv4 stub header
        auto pdu = sdap.tx(sdu);
        std::cout << "  SDAP PDU size=" << pdu.data.size() << "B (1B SDAP hdr + IP)\n\n";
    }

    // ----------------------------------------------------------------
    // 2. PDCP (TS 38.323) — COUNT, correct Tx order, SRB vs DRB
    // ----------------------------------------------------------------
    std::cout << "--- §2 PDCP (TS 38.323) — COUNT + correct Tx order ---\n";
    {
        // DRB: SN18, NEA2 cipher, no integrity (typical for eMBB DRB)
        PdcpConfig drb_cfg;
        drb_cfg.bearer_type  = BearerType::DRB;
        drb_cfg.sn_size      = PdcpSnSize::SN18;
        drb_cfg.cipher_algo  = CipherAlgo::NEA2;
        drb_cfg.integ_algo   = IntegAlgo::NIA0;
        drb_cfg.integ_on_drb = false;
        drb_cfg.bearer_id    = 1;
        drb_cfg.direction    = 0;
        PdcpTxEntity drb(drb_cfg);
        for (int i = 0; i < 3; ++i) {
            PdcpSdu s; s.data = bytes_t(20, uint8_t(0x10 + i));
            auto p = drb.tx(std::move(s));
            std::cout << "  DRB PDU size=" << p.data.size() << "B  COUNT=" << p.count << "\n";
        }

        std::cout << "\n";

        // SRB: SN12, NEA2 + NIA2 (always integrity-protected)
        PdcpConfig srb_cfg;
        srb_cfg.bearer_type  = BearerType::SRB;
        srb_cfg.sn_size      = PdcpSnSize::SN12;
        srb_cfg.cipher_algo  = CipherAlgo::NEA2;
        srb_cfg.integ_algo   = IntegAlgo::NIA2;
        srb_cfg.bearer_id    = 1;
        srb_cfg.direction    = 0;
        PdcpTxEntity srb(srb_cfg);
        PdcpSdu s2; s2.data = { 0x20, 0x01, 0x02, 0x03 };
        auto p2 = srb.tx(std::move(s2));
        std::cout << "  SRB PDU size=" << p2.data.size()
                  << "B (2B hdr + ciphered(payload+4B MAC-I))\n\n";

        // DRB with Rel-16 integrity protection
        PdcpConfig drb_integ_cfg;
        drb_integ_cfg.bearer_type  = BearerType::DRB;
        drb_integ_cfg.sn_size      = PdcpSnSize::SN18;
        drb_integ_cfg.cipher_algo  = CipherAlgo::NEA2;
        drb_integ_cfg.integ_algo   = IntegAlgo::NIA2;
        drb_integ_cfg.integ_on_drb = true;   // Rel-16 optional DRB integrity
        drb_integ_cfg.bearer_id    = 2;
        PdcpTxEntity drb2(drb_integ_cfg);
        PdcpSdu s3; s3.data = bytes_t(16, 0xFF);
        auto p3 = drb2.tx(std::move(s3));
        std::cout << "  DRB+integ PDU size=" << p3.data.size()
                  << "B (3B hdr + ciphered(payload) + 4B MAC-I)\n\n";
    }

    // ----------------------------------------------------------------
    // 3. RLC (TS 38.322) — correct PDU format
    // ----------------------------------------------------------------
    std::cout << "--- §3 RLC (TS 38.322) ---\n";
    {
        // AM SN12: show SN per SDU + SI field + STATUS PDU
        auto am = RlcFactory::create(RlcModeType::AM_SN12, 1);
        am->push_sdu(bytes_t(30, 0xAA)); // SDU-0: 30B → will be segmented with grant=20
        am->push_sdu(bytes_t(12, 0xBB)); // SDU-1: 12B

        std::cout << "\n  Grant=20: segmenting SDU-0\n";
        auto p1 = am->build_pdus(20);
        for (auto& p : p1)
            std::cout << "    AMD PDU SN=" << p.sn << " size=" << p.data.size()
                      << "B  D/C=" << ((p.data[0] >> 7) & 1)
                      << " P=" << ((p.data[0] >> 6) & 1)
                      << " SI=" << int((p.data[0] >> 4) & 0x03) << "\n";

        std::cout << "  Grant=40: remaining segments + SDU-1\n";
        auto p2 = am->build_pdus(40);
        for (auto& p : p2)
            std::cout << "    AMD PDU SN=" << p.sn << " size=" << p.data.size()
                      << "B  SI=" << int((p.data[0] >> 4) & 0x03) << "\n";

        // Receive STATUS PDU: ACK_SN=1 → SN=0 acknowledged
        std::cout << "\n  Rx STATUS PDU (ACK_SN=1, no NACKs):\n";
        RlcPdu status;
        status.is_ctrl = true;
        // 12-bit STATUS: [0x00|ACK[11:8]] [ACK[7:0]|E1=0] → ACK_SN=1
        status.data = { 0x00, 0x01 };
        am->rx_pdu(status);

        // UM SN6: show compact 1-byte header
        std::cout << "\n  UM-SN6 PDUs:\n";
        auto um = RlcFactory::create(RlcModeType::UM_SN6, 3);
        um->push_sdu(bytes_t(25, 0xCC));
        auto up = um->build_pdus(30);
        for (auto& p : up)
            std::cout << "    UMD PDU SN=" << p.sn << " size=" << p.data.size() << "B\n";
    }

    // ----------------------------------------------------------------
    // 4. RLC AM State Machine (Rel-16 suspend/resume)
    // ----------------------------------------------------------------
    std::cout << "\n--- §3.1 RLC AM State Machine (Rel-16 suspend/resume) ---\n";
    {
        RlcAmStateMachine sm;
        sm.on_establishment();
        std::cout << "  can_tx=" << (sm.can_tx() ? "yes" : "no") << "\n";
        sm.on_suspend();
        std::cout << "  can_tx=" << (sm.can_tx() ? "yes" : "no") << "\n";
        sm.on_resume();
        sm.on_release();
    }

    // ----------------------------------------------------------------
    // 5. MAC scheduler + HARQ (TS 38.321, TS 38.214)
    // ----------------------------------------------------------------
    std::cout << "\n--- §4 MAC Scheduler + HARQ (TS 38.321 / TS 38.214) ---\n";
    {
        MacScheduler sched;

        // Three UEs with different CQI
        UeContext u1; u1.rnti = 0xC001; u1.ul_buf = 1500; u1.dl_buf = 2000; u1.cqi = 12;
        UeContext u2; u2.rnti = 0xC002; u2.ul_buf =  600; u2.dl_buf =  400; u2.cqi = 8;
        UeContext u3; u3.rnti = 0xC003; u3.ul_buf =    0; u3.dl_buf =  300; u3.cqi = 14;
        sched.add_ue(u1); sched.add_ue(u2); sched.add_ue(u3);

        // Logical channels for UE1 (3 LCHs across 2 LCGs)
        LcConfig lc3_cfg; lc3_cfg.lcid=3; lc3_cfg.lcg=0; lc3_cfg.priority=1; lc3_cfg.pbr_bytes=500; lc3_cfg.bsd_ttis=4;
        LcConfig lc4_cfg; lc4_cfg.lcid=4; lc4_cfg.lcg=1; lc4_cfg.priority=3; lc4_cfg.pbr_bytes=200; lc4_cfg.bsd_ttis=4;
        LcConfig lc5_cfg; lc5_cfg.lcid=5; lc5_cfg.lcg=1; lc5_cfg.priority=5; lc5_cfg.pbr_bytes=100; lc5_cfg.bsd_ttis=4;
        LogicalChannel lc3(lc3_cfg), lc4(lc4_cfg), lc5(lc5_cfg);
        lc3.push(700); lc4.push(300); lc5.push(120);

        MacUeEntity ue1(0xC001, &sched);
        ue1.add_lch(&lc3); ue1.add_lch(&lc4); ue1.add_lch(&lc5);

        MacUeEntity ue2(0xC002, &sched);

        // TTI 0: UL scheduling — Round Robin across UEs with BSR pending
        sched.run_ul_tti(3000);

        // TTI 1: DL scheduling
        sched.run_dl_tti(3000);

        // TTI 2: UL scheduling again (remaining buffers)
        sched.run_ul_tti(3000);

        // HARQ retransmission: gNB signals RV=2 (2nd retx), then RV=3 (3rd retx)
        std::cout << "\n--- HARQ NACK/ACK with gNB-signalled RV (TS 38.214 §5.4.2.1) ---\n";
        sched.issue_ul_retx(0xC001, 0, 1); // retx#1 → RV=2
        sched.issue_ul_retx(0xC001, 0, 2); // retx#2 → RV=3
        ue1.ack_ul(0);                     // ACK   → HARQ process freed
    }

    std::cout << "\n=== Demo complete ===\n";
    return 0;
}
