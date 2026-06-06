module top_module( 
    input [99:0] a, b,
    input cin,
    output [99:0] cout,
    output [99:0] sum );

    // localparams
    localparam HDLBITS_NUM_OF_FA = 100;

    // wires
    reg    [HDLBITS_NUM_OF_FA-1:0] cin_tmp;
    integer i;
    always@(*) begin
        cin_tmp[0] = cin;
        for(i=1; i<HDLBITS_NUM_OF_FA; i=i+1) begin
            cin_tmp[i] = cout[i-1];
        end
    end

    // genfor
    genvar gi;
    generate for(gi=0; gi<HDLBITS_NUM_OF_FA; gi=gi+1) begin : g_fa
    	fa u_fa (.cin(cin_tmp[gi]), .x(a[gi]), .y(b[gi]), .cout(cout[gi]), .sum(sum[gi]) );
    end
    endgenerate
endmodule
        
module fa(
    input  cin ,
    input  x   ,
    input  y   ,
    output cout,
    output sum
);

assign {cout, sum} = {1'b0, cin} + {1'b0, x} + {1'b0, y};

endmodule
