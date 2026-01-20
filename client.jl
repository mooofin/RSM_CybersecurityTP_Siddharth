/* client.jl - TCP over UDP client implementation
 * Author: <redacted>
 * License: MIT
 *
 * Implements connection establishment, reliable data transfer with
 * retransmission, and graceful connection termination.
 */

using Sockets

#define SYN 0x01
#define ACK 0x02
#define FIN 0x04

const SYN=0x01; const ACK=0x02; const FIN=0x04

/* tunable parameters */
const TIMEOUT_MS = 500          /* retransmission timeout */
const MAX_RETRIES = 5           /* max retransmit attempts */
const PKT_SIZE = 100            /* max payload per packet */
const SIMULATE_LOSS = true      /* enable packet loss simulation */
const LOSS_RATE = 0.3           /* packet drop probability */

struct packet {
    seq_num::UInt32
    ack_num::UInt32
    flags::UInt8
    payload::Vector{UInt8}
}; const Packet = packet

@enum conn_state begin
    STATE_CLOSED
    STATE_SYN_SENT
    STATE_ESTABLISHED
    STATE_FIN_WAIT_1
    STATE_FIN_WAIT_2
    STATE_TIME_WAIT
end

const CLOSED=STATE_CLOSED; const SYN_SENT=STATE_SYN_SENT
const ESTABLISHED=STATE_ESTABLISHED; const FIN_WAIT_1=STATE_FIN_WAIT_1
const FIN_WAIT_2=STATE_FIN_WAIT_2; const TIME_WAIT=STATE_TIME_WAIT
const ConnectionState = conn_state

/* serialization primitives */
function serialize(p::packet)::Vector{UInt8}
    buf = IOBuffer()
    write(buf, hton(p.seq_num), hton(p.ack_num), p.flags, p.payload)
    return take!(buf)
end

function deserialize(data::Vector{UInt8})::packet
    buf = IOBuffer(data)
    return packet(
        ntoh(read(buf, UInt32)),
        ntoh(read(buf, UInt32)),
        read(buf, UInt8),
        read(buf)
    )
end

#define HAS_FLAG(pkt, flag) ((pkt.flags & flag) != 0)
has_flag(p::packet, f::UInt8) = (p.flags & f) != 0

function flags_str(f::UInt8)
    s = String[]
    (f & SYN) != 0 && push!(s, "SYN")
    (f & ACK) != 0 && push!(s, "ACK")
    (f & FIN) != 0 && push!(s, "FIN")
    return isempty(s) ? "NONE" : join(s, "+")
end


/* client connection context */
mutable struct client_conn
    state::conn_state
    sock::UDPSocket
    server_ip::IPv4
    server_port::Int
    local_seq::UInt32
    remote_seq::UInt32
    unacked::Dict{UInt32, Tuple{packet, Int}}
end; const Conn = client_conn

/* simulate packet loss for testing */
maybe_drop() = SIMULATE_LOSS && rand() < LOSS_RATE

/* send packet with optional simulated loss */
function send_pkt(ctx::client_conn, pkt::packet; can_drop=true)::Bool
    if can_drop && maybe_drop()
        @warn "simulated packet drop" seq=pkt.seq_num flags=flags_str(pkt.flags)
        return false
    end
    
    send(ctx.sock, ctx.server_ip, ctx.server_port, serialize(pkt))
    @debug "sent" seq=pkt.seq_num ack=pkt.ack_num flags=flags_str(pkt.flags) len=length(pkt.payload)
    return true
end

/* receive with timeout */
function recv_timeout(sock::UDPSocket, timeout_ms::Int)
    ch = Channel{Union{Tuple, Nothing}}(1)
    
    @async begin
        try
            addr, data = recvfrom(sock)
            put!(ch, (data, addr))
        catch e
            put!(ch, nothing)
        end
    end
    
    timer = Timer(timeout_ms / 1000)
    @async begin
        wait(timer)
        isready(ch) || put!(ch, nothing)
    end
    
    return take!(ch)
end

/* three-way handshake */
function connect!(ctx::client_conn)::Bool
    @info "initiating handshake"
    
    syn_pkt = packet(ctx.local_seq, 0, SYN, UInt8[])
    
    for attempt in 1:MAX_RETRIES
        send_pkt(ctx, syn_pkt, can_drop=false)
        @info "state transition" from="CLOSED" to="SYN_SENT"
        ctx.state = STATE_SYN_SENT
        
        result = recv_timeout(ctx.sock, TIMEOUT_MS)
        if result === nothing
            @warn "timeout waiting for SYN+ACK" attempt=attempt max=MAX_RETRIES
            continue
        end
        
        data, _ = result
        pkt = deserialize(data)
        @debug "recv" seq=pkt.seq_num ack=pkt.ack_num flags=flags_str(pkt.flags)
        
        if HAS_FLAG(pkt, SYN) && HAS_FLAG(pkt, ACK)
            if pkt.ack_num == ctx.local_seq + 1
                ctx.local_seq += 1
                ctx.remote_seq = pkt.seq_num + 1
                
                ack_pkt = packet(ctx.local_seq, ctx.remote_seq, ACK, UInt8[])
                send_pkt(ctx, ack_pkt, can_drop=false)
                
                @info "state transition" from="SYN_SENT" to="ESTABLISHED"
                ctx.state = STATE_ESTABLISHED
                @info "handshake complete"
                return true
            end
        end
    end
    
    @error "handshake failed"
    return false
end


/* reliable data transfer with retransmission */
function send_data!(ctx::client_conn, message::String)
    @info "starting data transfer"
    
    data = Vector{UInt8}(message)
    packets = packet[]
    seq = ctx.local_seq
    offset = 1
    
    /* fragment message into packets */
    while offset <= length(data)
        chunk_end = min(offset + PKT_SIZE - 1, length(data))
        chunk = data[offset:chunk_end]
        push!(packets, packet(seq, ctx.remote_seq, 0x00, chunk))
        seq += length(chunk)
        offset = chunk_end + 1
    end
    
    @info "fragmented message" num_packets=length(packets)
    
    /* send all packets */
    for pkt in packets
        ctx.unacked[pkt.seq_num] = (pkt, 0)
        send_pkt(ctx, pkt)
    end
    
    /* wait for ACKs with retransmission */
    while !isempty(ctx.unacked)
        result = recv_timeout(ctx.sock, TIMEOUT_MS)
        
        if result === nothing
            /* timeout - retransmit unacked packets */
            @warn "timeout - checking for retransmissions"
            to_remove = UInt32[]
            
            for (seq, (pkt, retries)) in ctx.unacked
                if retries >= MAX_RETRIES
                    @error "max retries exceeded" seq=seq
                    push!(to_remove, seq)
                else
                    @debug "retransmitting" seq=seq attempt=retries+1
                    send_pkt(ctx, pkt)
                    ctx.unacked[seq] = (pkt, retries + 1)
                end
            end
            
            for seq in to_remove
                delete!(ctx.unacked, seq)
            end
        else
            data, _ = result
            pkt = deserialize(data)
            @debug "recv ACK" ack_num=pkt.ack_num
            
            if HAS_FLAG(pkt, ACK)
                /* cumulative ACK - remove all seq < ack_num */
                to_remove = [seq for seq in keys(ctx.unacked) if seq < pkt.ack_num]
                for seq in to_remove
                    delete!(ctx.unacked, seq)
                    @debug "packet acknowledged" seq=seq
                end
                ctx.local_seq = max(ctx.local_seq, pkt.ack_num)
            end
        end
    end
    
    @info "all data acknowledged"
end


/* graceful connection termination */
function disconnect!(ctx::client_conn)
    @info "initiating connection termination"
    
    fin_pkt = packet(ctx.local_seq, ctx.remote_seq, FIN, UInt8[])
    
    /* send FIN and wait for ACK */
    for attempt in 1:MAX_RETRIES
        send_pkt(ctx, fin_pkt, can_drop=false)
        @info "state transition" from="ESTABLISHED" to="FIN_WAIT_1"
        ctx.state = STATE_FIN_WAIT_1
        
        result = recv_timeout(ctx.sock, TIMEOUT_MS)
        if result === nothing
            @warn "timeout waiting for ACK" attempt=attempt
            continue
        end
        
        data, _ = result
        pkt = deserialize(data)
        @debug "recv" seq=pkt.seq_num ack=pkt.ack_num flags=flags_str(pkt.flags)
        
        if HAS_FLAG(pkt, ACK)
            @info "state transition" from="FIN_WAIT_1" to="FIN_WAIT_2"
            ctx.state = STATE_FIN_WAIT_2
            break
        end
    end
    
    /* wait for server's FIN */
    if ctx.state == STATE_FIN_WAIT_2
        for attempt in 1:MAX_RETRIES
            result = recv_timeout(ctx.sock, TIMEOUT_MS * 2)
            if result === nothing
                @warn "timeout waiting for FIN" attempt=attempt
                continue
            end
            
            data, _ = result
            pkt = deserialize(data)
            @debug "recv" seq=pkt.seq_num ack=pkt.ack_num flags=flags_str(pkt.flags)
            
            if HAS_FLAG(pkt, FIN)
                ctx.remote_seq = pkt.seq_num + 1
                
                /* send final ACK */
                ack_pkt = packet(ctx.local_seq, ctx.remote_seq, ACK, UInt8[])
                send_pkt(ctx, ack_pkt, can_drop=false)
                
                @info "state transition" from="FIN_WAIT_2" to="TIME_WAIT"
                ctx.state = STATE_TIME_WAIT
                sleep(0.1)  /* brief TIME_WAIT */
                
                @info "state transition" from="TIME_WAIT" to="CLOSED"
                ctx.state = STATE_CLOSED
                break
            end
        end
    end
    
    close(ctx.sock)
    @info "connection closed"
end

/* main entry point */
function main()
    sock = UDPSocket()
    bind(sock, ip"0.0.0.0", 0)
    
    ctx = client_conn(
        STATE_CLOSED,
        sock,
        ip"127.0.0.1",
        9000,
        rand(UInt32) % 1000,
        0,
        Dict{UInt32, Tuple{packet, Int}}()
    )
    
    @info "TCP-over-UDP client" loss_sim=SIMULATE_LOSS loss_rate=LOSS_RATE
    
    /* establish connection */
    if !connect!(ctx)
        close(sock)
        return
    end
    
    /* send test message */
    message = """
    Hello from TCP-over-UDP client!
    This is a multi-packet message to demonstrate reliable delivery.
    Line 3: The protocol handles packet loss through retransmission.
    Line 4: Sequence numbers ensure ordered delivery.
    Line 5: ACKs confirm receipt of data.
    Line 6: This is the end of the test message.
    """
    
    send_data!(ctx, message)
    
    /* terminate connection */
    disconnect!(ctx)
end

/* entry point */
if abspath(PROGRAM_FILE) == @__FILE__
    main()
end
