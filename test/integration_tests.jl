using Test, Sockets
include("../server.jl")

@testset "UDP Sockets" begin
    @testset "basic" begin
        s = UDPSocket(); bind(s, ip"127.0.0.1", 19001)
        c = UDPSocket(); bind(c, ip"0.0.0.0", 0)
        send(c, ip"127.0.0.1", 19001, serialize(Packet(123, 456, SYN, Vector{UInt8}("test"))))
        _, d = recvfrom(s); p = deserialize(d)
        @test p.seq_num == 123 && has_flag(p,SYN) && String(p.payload) == "test"
        close(s); close(c)
    end

    @testset "bidirectional" begin
        s1 = UDPSocket(); bind(s1, ip"127.0.0.1", 19002)
        s2 = UDPSocket(); bind(s2, ip"127.0.0.1", 19003)
        send(s1, ip"127.0.0.1", 19003, serialize(Packet(100,0,SYN,UInt8[])))
        _,d1 = recvfrom(s2); @test deserialize(d1).seq_num == 100
        send(s2, ip"127.0.0.1", 19002, serialize(Packet(200,101,SYN|ACK,UInt8[])))
        _,d2 = recvfrom(s1); @test deserialize(d2).seq_num == 200
        close(s1); close(s2)
    end

    @testset "large packet" begin
        s = UDPSocket(); bind(s, ip"127.0.0.1", 19004)
        c = UDPSocket(); bind(c, ip"0.0.0.0", 0)
        big = rand(UInt8, 1000)
        send(c, ip"127.0.0.1", 19004, serialize(Packet(1,1,ACK,big)))
        _,d = recvfrom(s); @test deserialize(d).payload == big
        close(s); close(c)
    end

    @testset "sequential" begin
        s = UDPSocket(); bind(s, ip"127.0.0.1", 19005)
        c = UDPSocket(); bind(c, ip"0.0.0.0", 0)
        for i::UInt32 in 1:10; send(c, ip"127.0.0.1", 19005, serialize(Packet(i*100,0,0x00,Vector{UInt8}("pkt$i")))) end
        recv = [deserialize(recvfrom(s)[2]) for _ in 1:10]
        @test length(recv) == 10
        close(s); close(c)
    end
end

@testset "Protocol Flow" begin
    @testset "handshake sim" begin
        cseq::UInt32, sseq::UInt32 = 100, 200
        cstate, sstate = :CLOSED, :LISTEN

        syn = Packet(cseq, 0, SYN, UInt8[]); cstate = :SYN_SENT
        @test has_flag(syn,SYN) && !has_flag(syn,ACK)

        sstate = :SYN_RECEIVED
        syn_ack = Packet(sseq, cseq+1, SYN|ACK, UInt8[])
        @test syn_ack.ack_num == cseq+1

        cseq += 1
        ack = Packet(cseq, sseq+1, ACK, UInt8[])
        cstate = :ESTABLISHED; sstate = :ESTABLISHED
        @test cstate == :ESTABLISHED && sstate == :ESTABLISHED
    end

    @testset "data transfer sim" begin
        cseq::UInt32, sseq::UInt32 = 101, 201
        sexp::UInt32 = 101
        msg = "Hello from client!"
        data_p = Packet(cseq, sseq, 0x00, Vector{UInt8}(msg))
        @test data_p.seq_num == sexp
        sexp += length(msg)
        ack_p = Packet(sseq, sexp, ACK, UInt8[])
        @test ack_p.ack_num == 101 + 18
    end

    @testset "out-of-order" begin
        sexp::UInt32 = 100
        buf = Dict{UInt32,Vector{UInt8}}()
        delivered = IOBuffer()
        pkts = [Packet(200,0,0x00,Vector{UInt8}("second")), Packet(300,0,0x00,Vector{UInt8}("third")), Packet(100,0,0x00,Vector{UInt8}("first"))]
        for p in pkts
            if p.seq_num == sexp
                write(delivered, p.payload); sexp += length(p.payload)
                while haskey(buf,sexp); b=pop!(buf,sexp); write(delivered,b); sexp+=length(b) end
            elseif p.seq_num > sexp
                buf[p.seq_num] = p.payload
            end
        end
        seekstart(delivered); @test String(read(delivered)) == "first"
        @test haskey(buf,200) && haskey(buf,300)
    end

    @testset "consecutive ooo" begin
        sexp::UInt32 = 100
        buf = Dict{UInt32,Vector{UInt8}}()
        delivered = IOBuffer()
        pkts = [Packet(110,0,0x00,zeros(UInt8,10)), Packet(120,0,0x00,zeros(UInt8,10)), Packet(100,0,0x00,zeros(UInt8,10))]
        for p in pkts
            if p.seq_num == sexp
                write(delivered, p.payload); sexp += length(p.payload)
                while haskey(buf,sexp); b=pop!(buf,sexp); write(delivered,b); sexp+=length(b) end
            elseif p.seq_num > sexp
                buf[p.seq_num] = p.payload
            end
        end
        @test sexp == 130 && isempty(buf) && position(delivered) == 30
    end
end

@testset "Termination" begin
    cseq::UInt32, sseq::UInt32 = 1000, 500
    cstate, sstate = :ESTABLISHED, :ESTABLISHED

    cfin = Packet(cseq, sseq, FIN, UInt8[]); cstate = :FIN_WAIT_1
    @test has_flag(cfin, FIN)

    sstate = :CLOSE_WAIT
    sack = Packet(sseq, cseq+1, ACK, UInt8[])
    @test sack.ack_num == 1001
    cstate = :FIN_WAIT_2

    sfin = Packet(sseq, cseq+1, FIN, UInt8[]); sstate = :LAST_ACK
    cack = Packet(cseq+1, sseq+1, ACK, UInt8[]); cstate = :TIME_WAIT
    @test cack.ack_num == 501

    sstate = :CLOSED; cstate = :CLOSED
    @test sstate == :CLOSED && cstate == :CLOSED
end

@testset "Retransmit" begin
    @testset "timeout" begin
        unacked = Dict{UInt32,Tuple{Packet,Int}}()
        p = Packet(100, 0, 0x00, Vector{UInt8}("data"))
        unacked[100] = (p, 0)
        for i in 1:3; old,ret = unacked[100]; @test ret == i-1; unacked[100] = (old, ret+1) end
        @test unacked[100][2] == 3
    end

    @testset "ack clears" begin
        unacked = Dict{UInt32,Tuple{Packet,Int}}()
        for seq::UInt32 in [100,150,200,250]; unacked[seq] = (Packet(seq,0,0x00,zeros(UInt8,50)),0) end
        ack::UInt32 = 200
        for s in [s for s in keys(unacked) if s < ack]; delete!(unacked,s) end
        @test length(unacked) == 2 && !haskey(unacked,100) && haskey(unacked,200)
    end

    @testset "dup ack" begin
        unacked = Dict{UInt32,Tuple{Packet,Int}}()
        unacked[100] = (Packet(100,0,0x00,zeros(UInt8,50)),0)
        ack::UInt32 = 100
        for _ in 1:3; for s in [s for s in keys(unacked) if s < ack]; delete!(unacked,s) end end
        @test haskey(unacked, 100)
    end
end

@testset "State Machine" begin
    transitions = [(LISTEN,SYN_RECEIVED), (SYN_RECEIVED,ESTABLISHED), (ESTABLISHED,CLOSE_WAIT), (CLOSE_WAIT,LAST_ACK), (LAST_ACK,CLOSED)]
    state = LISTEN
    for (from,to) in transitions; @test state == from; state = to end
    @test state == CLOSED

    state = LISTEN
    ack_p = Packet(0,0,ACK,UInt8[])
    (state == LISTEN && has_flag(ack_p,SYN) && !has_flag(ack_p,ACK)) && (state = SYN_RECEIVED)
    @test state == LISTEN
end

@testset "Stress" begin
    @testset "many packets" begin
        pkts = [Packet(UInt32(i), UInt32(i+1), i%2==0 ? ACK : 0x00, rand(UInt8,100)) for i in 1:1000]
        for p in pkts; r = deserialize(serialize(p)); @test r.seq_num == p.seq_num && r.payload == p.payload end
    end

    @testset "large buffer" begin
        buf = Dict{UInt32,Vector{UInt8}}()
        for i::UInt32 in 1:1000; buf[i*100] = rand(UInt8,50) end
        @test length(buf) == 1000
        thresh::UInt32 = 50000
        for s in [s for s in keys(buf) if s < thresh]; delete!(buf,s) end
        @test length(buf) == 501
    end

    @testset "rapid state" begin
        conn = ServerConnection(LISTEN, nothing, 0, 0, Dict{UInt32,Vector{UInt8}}())
        states = [LISTEN, SYN_RECEIVED, ESTABLISHED, CLOSE_WAIT, LAST_ACK, CLOSED]
        for _ in 1:100; for s in states; conn.state = s; @test conn.state == s end end
    end
end

println("\n✓ All integration tests passed!")
