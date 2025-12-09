module top_module(
    input [31:0] a,
    input [31:0] b,
    output [31:0] sum
);

    wire [15:0] w_a_lsb;
    wire [15:0] w_b_lsb;
    wire [15:0] w_a_msb;
    wire [15:0] w_b_msb;

    wire        w_cout0;
    wire        w_cout1;
    wire [15:0] w_sum0;
    wire [15:0] w_sum1;


    assign w_a_lsb = a[15: 0];
    assign w_b_lsb = b[15: 0];

    assign w_a_msb = a[31:16];
    assign w_b_msb = b[31:16];

    add16 u_add16_0 (.a(w_a_lsb),
                     .b(w_b_lsb),
                     .cin(1'b0),
                     .sum(w_sum0),
                     .cout(w_cout0));
    add16 u_add16_1 (.a(w_a_msb),
                     .b(w_b_msb),
                     .cin(w_cout0),
                     .sum(w_sum1),
                     .cout(w_cout1));
    assign sum = {w_sum1, w_sum0};
endmodule

// below part is for only compile, not for HDLBits Site Answers.
module add16(

    input  [15:0]  a,
    input  [15:0]  b,
    input          cin,
    output [15:0]  sum,
    output         cout
);

wire [16:0] w_sum;

assign w_sum = a + b + cin;
assign sum  = w_sum[15:0];
assign cout = w_sum[16];

endmodule