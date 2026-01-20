/* server.jl - TCP over UDP implementation
 * Author: <redacted>
 * License: MIT
 * 
 * Reliable transport layer over unreliable UDP datagrams.
 * Implements connection establishment, ordered delivery, and graceful shutdown.
 */

using Sockets

#define SYN 0x01
#define ACK 0x02  
#define FIN 0x04

const SYN=0x01; const ACK=0x02; const FIN=0x04

struct packet {
    seq_num::UInt32
    ack_num::UInt32
    flags::UInt8
    payload::Vector{UInt8}
}; const Packet = packet

@enum conn_state begin
    STATE_CLOSED
    STATE_LISTEN
    STATE_SYN_RCVD
    STATE_ESTABLISHED
    STATE_FIN_WAIT
    STATE_CLOSE_WAIT
    STATE_LAST_ACK
    STATE_TIME_WAIT
end

const CLOSED=STATE_CLOSED; const LISTEN=STATE_LISTEN
const SYN_RECEIVED=STATE_SYN_RCVD; const ESTABLISHED=STATE_ESTABLISHED
const FIN_WAIT=STATE_FIN_WAIT; const CLOSE_WAIT=STATE_CLOSE_WAIT
const LAST_ACK=STATE_LAST_ACK; const TIME_WAIT=STATE_TIME_WAIT
const ConnectionState = conn_state

/* packet serialization - network byte order */
function serialize(p::packet)::Vector{UInt8}
    buf = IOBuffer()
    write(buf, hton(p.seq_num))
    write(buf, hton(p.ack_num))
    write(buf, p.flags)
    write(buf, p.payload)
    return take!(buf)
end

/* packet deserialization */
function deserialize(data::Vector{UInt8})::packet
    buf = IOBuffer(data)
    seq = ntoh(read(buf, UInt32))
    ack = ntoh(read(buf, UInt32))
    flg = read(buf, UInt8)
    pld = read(buf)
    return packet(seq, ack, flg, pld)
end

#define HAS_FLAG(pkt, flag) ((pkt.flags & flag) != 0)
has_flag(p::packet, f::UInt8) = (p.flags & f) != 0

function flags_str(f::UInt8)
    parts = String[]
    (f & SYN) != 0 && push!(parts, "SYN")
    (f & ACK) != 0 && push!(parts, "ACK")
    (f & FIN) != 0 && push!(parts, "FIN")
    return isempty(parts) ? "NONE" : join(parts, "+")
end


/* server connection context */
mutable struct server_conn
    state::conn_state
    client_addr::Any
    local_seq::UInt32
    remote_seq::UInt32
    recv_buffer::Dict{UInt32, Vector{UInt8}}
end; const ServerConnection = server_conn

/* main server loop - handles incoming datagrams */
function run_server(port::Int)
    sock = UDPSocket()
    bind(sock, ip"0.0.0.0", port)
    
    @info "server listening" port=port
    
    ctx = server_conn(
        STATE_LISTEN,
        nothing,
        rand(UInt32) % 1000,
        0,
        Dict{UInt32, Vector{UInt8}}()
    )
    
    recv_buf = IOBuffer()
    
    while ctx.state != STATE_CLOSED
        addr, dgram = recvfrom(sock)
        pkt = deserialize(dgram)
        
        @debug "recv" seq=pkt.seq_num ack=pkt.ack_num flags=flags_str(pkt.flags) len=length(pkt.payload)
        
        /* state machine */
        if ctx.state == STATE_LISTEN
            if HAS_FLAG(pkt, SYN) && !HAS_FLAG(pkt, ACK)
                @info "state transition" from="LISTEN" to="SYN_RCVD"
                ctx.client_addr = addr
                ctx.remote_seq = pkt.seq_num + 1
                
                syn_ack = packet(ctx.local_seq, ctx.remote_seq, SYN | ACK, UInt8[])
                send(sock, addr.host, addr.port, serialize(syn_ack))
                @debug "sent SYN+ACK"
                
                ctx.state = STATE_SYN_RCVD
            end
            
        elseif ctx.state == STATE_SYN_RCVD
            if HAS_FLAG(pkt, ACK) && !HAS_FLAG(pkt, SYN)
                if pkt.ack_num == ctx.local_seq + 1
                    @info "state transition" from="SYN_RCVD" to="ESTABLISHED"
                    ctx.local_seq += 1
                    ctx.state = STATE_ESTABLISHED
                end
            end

            
        elseif ctx.state == STATE_ESTABLISHED
            if HAS_FLAG(pkt, FIN)
                @info "state transition" from="ESTABLISHED" to="CLOSE_WAIT"
                ctx.remote_seq = pkt.seq_num + 1
                
                ack_pkt = packet(ctx.local_seq, ctx.remote_seq, ACK, UInt8[])
                send(sock, addr.host, addr.port, serialize(ack_pkt))
                @debug "sent ACK for FIN"
                
                ctx.state = STATE_CLOSE_WAIT
                
                /* dump received data */
                seekstart(recv_buf)
                msg = String(read(recv_buf))
                println("\n" * "="^60)
                println("RECEIVED MESSAGE:")
                println("="^60)
                print(msg)
                println("="^60 * "\n")
                
                sleep(0.1)
                
                fin_pkt = packet(ctx.local_seq, ctx.remote_seq, FIN, UInt8[])
                send(sock, addr.host, addr.port, serialize(fin_pkt))
                @info "state transition" from="CLOSE_WAIT" to="LAST_ACK"
                ctx.state = STATE_LAST_ACK
                
            elseif !HAS_FLAG(pkt, SYN) && length(pkt.payload) > 0
                /* data packet */
                if pkt.seq_num == ctx.remote_seq
                    /* in-order delivery */
                    write(recv_buf, pkt.payload)
                    ctx.remote_seq += length(pkt.payload)
                    @debug "delivered in-order" bytes=length(pkt.payload)
                    
                    /* check for buffered packets */
                    while haskey(ctx.recv_buffer, ctx.remote_seq)
                        buffered = pop!(ctx.recv_buffer, ctx.remote_seq)
                        write(recv_buf, buffered)
                        ctx.remote_seq += length(buffered)
                        @debug "delivered buffered" bytes=length(buffered)
                    end
                    
                elseif pkt.seq_num > ctx.remote_seq
                    /* out-of-order - buffer it */
                    ctx.recv_buffer[pkt.seq_num] = pkt.payload
                    @debug "buffered out-of-order" seq=pkt.seq_num
                end
                
                /* send ACK */
                ack_pkt = packet(ctx.local_seq, ctx.remote_seq, ACK, UInt8[])
                send(sock, addr.host, addr.port, serialize(ack_pkt))
                @debug "sent ACK" ack_num=ctx.remote_seq
            end
            
        elseif ctx.state == STATE_LAST_ACK
            if HAS_FLAG(pkt, ACK)
                @info "state transition" from="LAST_ACK" to="CLOSED"
                ctx.state = STATE_CLOSED
            end
        end
    end
    
    close(sock)
    @info "connection closed"
end

/* entry point */
if abspath(PROGRAM_FILE) == @__FILE__
    run_server(9000)
end
