using Test, Sockets
include("../server.jl")

@testset "Packet Tests" begin
    @testset "serialization" begin
        p = Packet(100, 200, SYN|ACK, UInt8[])
        r = deserialize(serialize(p))
        @test r.seq_num == 100 && r.ack_num == 200 && r.flags == (SYN|ACK)

        payload = Vector{UInt8}("Hello, World!")
        p2 = Packet(1, 2, ACK, payload)
        r2 = deserialize(serialize(p2))
        @test String(r2.payload) == "Hello, World!"

        empty_pkt = Packet(0, 0, 0x00, UInt8[])
        @test length(serialize(empty_pkt)) == 9
        @test length(serialize(Packet(0,0,0x00,zeros(UInt8,100)))) == 109
    end

    @testset "byte order" begin
        p = Packet(0x01020304, 0x05060708, 0x00, UInt8[])
        d = serialize(p)
        @test d[1:4] == [0x01,0x02,0x03,0x04]
        @test d[5:8] == [0x05,0x06,0x07,0x08]
    end

    @testset "boundaries" begin
        min_p = Packet(UInt32(0), UInt32(0), 0x00, UInt8[])
        max_p = Packet(typemax(UInt32), typemax(UInt32), 0xFF, UInt8[])
        @test deserialize(serialize(min_p)).seq_num == 0
        @test deserialize(serialize(max_p)).seq_num == typemax(UInt32)
    end

    @testset "binary payload" begin
        for payload in [UInt8[0x00,0x00], UInt8[0xFF,0xFF], rand(UInt8,10000)]
            @test deserialize(serialize(Packet(1,1,0x00,payload))).payload == payload
        end
        unicode = Vector{UInt8}("Hello, 世界! 🌍")
        @test String(deserialize(serialize(Packet(1,1,0x00,unicode))).payload) == "Hello, 世界! 🌍"
    end
end

@testset "Flags" begin
    @test SYN == 0x01 && ACK == 0x02 && FIN == 0x04
    @test SYN & ACK == 0 && SYN & FIN == 0 && ACK & FIN == 0

    syn_p = Packet(0,0,SYN,UInt8[])
    @test has_flag(syn_p,SYN) && !has_flag(syn_p,ACK) && !has_flag(syn_p,FIN)

    combo = Packet(0,0,SYN|ACK|FIN,UInt8[])
    @test has_flag(combo,SYN) && has_flag(combo,ACK) && has_flag(combo,FIN)

    @test flags_str(0x00) == "NONE"
    @test flags_str(SYN) == "SYN"
    @test flags_str(SYN|ACK) == "SYN+ACK"
    @test flags_str(SYN|ACK|FIN) == "SYN+ACK+FIN"

    for f in [0x00, SYN, ACK, FIN, SYN|ACK, SYN|FIN, ACK|FIN, SYN|ACK|FIN]
        @test deserialize(serialize(Packet(0,0,f,UInt8[]))).flags == f
    end
end

@testset "Connection State" begin
    @test CLOSED isa ConnectionState && LISTEN isa ConnectionState && ESTABLISHED isa ConnectionState
    conn = ServerConnection(LISTEN, nothing, 100, 0, Dict{UInt32,Vector{UInt8}}())
    @test conn.state == LISTEN && conn.local_seq == 100 && isempty(conn.recv_buffer)
    conn.state = ESTABLISHED; conn.local_seq += 1
    @test conn.state == ESTABLISHED && conn.local_seq == 101
end

@testset "Buffer Ops" begin
    buf = Dict{UInt32,Vector{UInt8}}()
    buf[100] = UInt8[1,2,3]; buf[200] = UInt8[4,5,6]
    @test length(buf) == 2 && haskey(buf,100)
    d = pop!(buf,100)
    @test d == UInt8[1,2,3] && !haskey(buf,100)
end

@testset "Seq Numbers" begin
    seq::UInt32 = 100; seq += 50; @test seq == 150
    seq = 100; seq += 1; @test seq == 101  # SYN/FIN consume 1

    unacked = Dict{UInt32,Tuple{Packet,Int}}()
    unacked[100] = (Packet(100,0,0x00,zeros(UInt8,50)),0)
    unacked[150] = (Packet(150,0,0x00,zeros(UInt8,50)),0)
    unacked[200] = (Packet(200,0,0x00,zeros(UInt8,50)),0)
    ack::UInt32 = 175
    for s in [s for s in keys(unacked) if s < ack]; delete!(unacked,s) end
    @test length(unacked) == 1 && haskey(unacked,200)

    seq = typemax(UInt32) - 10; seq += 20; @test seq == 9
end

@testset "Handshake Packets" begin
    cseq::UInt32, sseq::UInt32 = 100, 200
    syn = Packet(cseq, 0, SYN, UInt8[])
    @test has_flag(syn,SYN) && !has_flag(syn,ACK) && syn.ack_num == 0

    syn_ack = Packet(sseq, cseq+1, SYN|ACK, UInt8[])
    @test has_flag(syn_ack,SYN) && has_flag(syn_ack,ACK) && syn_ack.ack_num == 101

    ack = Packet(cseq+1, sseq+1, ACK, UInt8[])
    @test !has_flag(ack,SYN) && has_flag(ack,ACK) && ack.ack_num == 201
end

@testset "Data Packets" begin
    data_p = Packet(500, 300, 0x00, Vector{UInt8}("Hello!"))
    @test !has_flag(data_p,SYN) && !has_flag(data_p,FIN) && length(data_p.payload) == 6

    msg = "This is a longer message that needs chunking for transmission over the wire."
    data, pkt_size = Vector{UInt8}(msg), 20
    pkts = Packet[]; seq::UInt32 = 100; i = 1
    while i <= length(data)
        j = min(i+pkt_size-1, length(data))
        push!(pkts, Packet(seq, 0, 0x00, data[i:j]))
        seq += j-i+1; i = j+1
    end
    @test length(pkts) == 4
    total = UInt8[]; for p in pkts; append!(total, p.payload) end
    @test String(total) == msg
end

@testset "FIN Packets" begin
    cseq::UInt32, sseq::UInt32 = 1000, 500
    fin = Packet(cseq, sseq, FIN, UInt8[])
    @test has_flag(fin,FIN) && !has_flag(fin,ACK)
    fin_ack = Packet(sseq, cseq+1, ACK, UInt8[])
    @test has_flag(fin_ack,ACK) && fin_ack.ack_num == 1001
end

@testset "Retransmit Logic" begin
    unacked = Dict{UInt32,Tuple{Packet,Int}}()
    p = Packet(100, 0, 0x00, UInt8[1,2,3])
    unacked[100] = (p, 0)
    for _ in 1:3; old,ret = unacked[100]; unacked[100] = (old, ret+1) end
    @test unacked[100][2] == 3

    unacked[100] = (p, 5)
    _,ret = unacked[100]; ret >= 5 && delete!(unacked, 100)
    @test isempty(unacked)
end

@testset "Edge Cases" begin
    min_data = zeros(UInt8, 9)
    p = deserialize(min_data)
    @test p.seq_num == 0 && p.ack_num == 0 && isempty(p.payload)

    max_flags = Packet(0, 0, 0xFF, UInt8[])
    @test has_flag(max_flags,SYN) && has_flag(max_flags,ACK) && has_flag(max_flags,FIN)

    pkt = Packet(12345, 67890, SYN|ACK, Vector{UInt8}("test"))
    curr = pkt
    for _ in 1:10; curr = deserialize(serialize(curr)) end
    @test curr.seq_num == pkt.seq_num && curr.payload == pkt.payload

    buf = Dict{UInt32,Vector{UInt8}}()
    for i::UInt32 in 1:100; buf[i*100] = rand(UInt8,10) end
    @test length(buf) == 100
    for i::UInt32 in 1:50; delete!(buf, i*100) end
    @test length(buf) == 50
end

println("\n✓ All tests passed!")
