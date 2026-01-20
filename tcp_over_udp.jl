# TCP-like Protocol over UDP in Julia
# Implements: 3-way handshake, sequenced data transfer, retransmission, FIN termination

using Sockets

# Packet types
const SYN = 0x01
const SYN_ACK = 0x02
const ACK = 0x03
const DATA = 0x04
const FIN = 0x05
const FIN_ACK = 0x06

# Configuration
const TIMEOUT_SEC = 2.0
const MAX_RETRIES = 5

# Packet structure
struct Packet
    type::UInt8
    seq_num::UInt32
    ack_num::UInt32
    data::Vector{UInt8}
end

# Serialize packet to bytes
function serialize(pkt::Packet)::Vector{UInt8}
    buf = IOBuffer()
    write(buf, pkt.type)
    write(buf, hton(pkt.seq_num))
    write(buf, hton(pkt.ack_num))
    write(buf, hton(UInt16(length(pkt.data))))
    write(buf, pkt.data)
    return take!(buf)
end

# Deserialize bytes to packet
function deserialize(data::Vector{UInt8})::Packet
    buf = IOBuffer(data)
    type = read(buf, UInt8)
    seq_num = ntoh(read(buf, UInt32))
    ack_num = ntoh(read(buf, UInt32))
    data_len = ntoh(read(buf, UInt16))
    payload = read(buf, data_len)
    return Packet(type, seq_num, ack_num, payload)
end

# Connection state
mutable struct Connection
    socket::UDPSocket
    local_port::UInt16
    remote_addr::IPAddr
    remote_port::UInt16
    seq_num::UInt32
    ack_num::UInt32
    connected::Bool
    recv_channel::Channel{Tuple}
    recv_task::Union{Task, Nothing}
end

# Start background receiver task
function start_receiver!(conn::Connection)
    conn.recv_task = @async begin
        while isopen(conn.socket)
            try
                result = recvfrom(conn.socket)
                put!(conn.recv_channel, result)
            catch e
                if isopen(conn.socket)
                    println("[ERROR] Receive error: $e")
                end
                break
            end
        end
    end
end

# Receive with timeout from channel
function recv_with_timeout(conn::Connection, timeout::Float64)::Union{Tuple, Nothing}
    start_time = time()
    while (time() - start_time) < timeout
        if isready(conn.recv_channel)
            return take!(conn.recv_channel)
        end
        sleep(0.01)
    end
    return nothing
end


# Send packet with retransmission
function send_with_retry(conn::Connection, pkt::Packet, expected_type::UInt8)::Union{Packet, Nothing}
    data = serialize(pkt)
    
    for attempt in 1:MAX_RETRIES
        send(conn.socket, conn.remote_addr, conn.remote_port, data)
        println("[SEND] Type=$(pkt.type), Seq=$(pkt.seq_num), Ack=$(pkt.ack_num), Attempt=$attempt")
        
        result = recv_with_timeout(conn, TIMEOUT_SEC)
        
        if result !== nothing
            addr, response_data = result
            response = deserialize(response_data)
            println("[RECV] Type=$(response.type), Seq=$(response.seq_num), Ack=$(response.ack_num)")
            
            if response.type == expected_type
                return response
            end
        else
            println("[TIMEOUT] Retrying...")
        end
    end
    return nothing
end

# ============== CLIENT FUNCTIONS ==============

# Three-way handshake (client side)
function connect_to_server(local_port::Int, remote_host::String, remote_port::Int)::Union{Connection, Nothing}
    socket = UDPSocket()
    bind(socket, ip"0.0.0.0", local_port)
    
    conn = Connection(
        socket,
        UInt16(local_port),
        getaddrinfo(remote_host),
        UInt16(remote_port),
        rand(UInt32) % 10000,
        0,
        false,
        Channel{Tuple}(32),
        nothing
    )
    
    # Start background receiver
    start_receiver!(conn)
    
    println("\n=== Starting 3-Way Handshake (Client) ===")
    
    # Step 1: Send SYN
    syn_pkt = Packet(SYN, conn.seq_num, 0, UInt8[])
    response = send_with_retry(conn, syn_pkt, SYN_ACK)
    
    if response === nothing
        println("[ERROR] Handshake failed: No SYN-ACK received")
        close(socket)
        return nothing
    end
    
    # Step 2: Received SYN-ACK, update state
    conn.ack_num = response.seq_num + 1
    conn.seq_num += 1
    
    # Step 3: Send ACK
    ack_pkt = Packet(ACK, conn.seq_num, conn.ack_num, UInt8[])
    send(conn.socket, conn.remote_addr, conn.remote_port, serialize(ack_pkt))
    println("[SEND] ACK - Handshake complete!")
    
    conn.connected = true
    println("=== Connection Established ===\n")
    return conn
end

# Send data with sequencing and acknowledgement
function send_data(conn::Connection, message::String)::Bool
    if !conn.connected
        println("[ERROR] Not connected")
        return false
    end
    
    println("\n=== Sending Data ===")
    data_pkt = Packet(DATA, conn.seq_num, conn.ack_num, Vector{UInt8}(message))
    response = send_with_retry(conn, data_pkt, ACK)
    
    if response === nothing
        println("[ERROR] Data transfer failed: No ACK received")
        return false
    end
    
    expected_ack = conn.seq_num + UInt32(length(message))
    if response.ack_num == expected_ack
        conn.seq_num = expected_ack
        println("[SUCCESS] Data acknowledged")
        return true
    end
    
    println("[ERROR] Unexpected ACK number: got $(response.ack_num), expected $expected_ack")
    return false
end

# Connection termination (client initiates)
function disconnect(conn::Connection)::Bool
    if !conn.connected
        return true
    end
    
    println("\n=== Connection Termination ===")
    
    # Send FIN
    fin_pkt = Packet(FIN, conn.seq_num, conn.ack_num, UInt8[])
    response = send_with_retry(conn, fin_pkt, FIN_ACK)
    
    if response === nothing
        println("[ERROR] Termination failed: No FIN-ACK received")
        close(conn.socket)
        conn.connected = false
        return false
    end
    
    # Send final ACK
    conn.seq_num += 1
    conn.ack_num = response.seq_num + 1
    final_ack = Packet(ACK, conn.seq_num, conn.ack_num, UInt8[])
    send(conn.socket, conn.remote_addr, conn.remote_port, serialize(final_ack))
    println("[SEND] Final ACK - Connection closed")
    
    close(conn.socket)
    close(conn.recv_channel)
    conn.connected = false
    println("=== Connection Terminated ===\n")
    return true
end
