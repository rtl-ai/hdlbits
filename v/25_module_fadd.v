module top_module (
    input [31:0] a,
    input [31:0] b,
    output [31:0] sum
);

wire [15:0] w_lsb_a;
wire [15:0] w_lsb_b;
wire [15:0] w_lsb_sum;
wire        w_lsb_cout;

wire [15:0] w_msb_a;
wire [15:0] w_msb_b;
wire [15:0] w_msb_sum;
wire        w_msb_cout;

assign {w_msb_a, w_lsb_a} = a;
assign {w_msb_b, w_lsb_b} = b;

add16 u_add16_0 (.a(w_lsb_a), .b(w_lsb_b), .cin(1'b0),       .sum(w_lsb_sum), .cout(w_lsb_cout));
add16 u_add16_1 (.a(w_msb_a), .b(w_msb_b), .cin(w_lsb_cout), .sum(w_msb_sum), .cout(w_msb_cout));

assign sum = {w_msb_sum, w_lsb_sum};

endmodule

// only for ci checks, not for HDLbits.
module add16 (
    input  [15:0] a,
    input  [15:0] b,
    input         cin,
    output [15:0] sum,
    output        cout
);
    wire [15:0] w_a;
    wire [15:0] w_b;
    wire [15:0] w_cins;
    wire [15:0] w_couts;
    wire [15:0] w_sums;
    assign w_a = a;
    assign w_b = b;
    assign w_cins[0] = cin;
    assign w_cins[15:1] = w_couts[14:0];

    genvar adder_idx;
    generate
        for(adder_idx=0; adder_idx < 16; adder_idx = adder_idx + 1) begin : gen_adder1
            add1 u_add1 (.a(w_a[adder_idx]),
                        .b(w_b[adder_idx]),
                        .cin(w_cins[adder_idx]),
                        .sum(w_sums[adder_idx]),
                        .cout(w_couts[adder_idx]));
        end
    endgenerate

assign sum = w_sums;
assign cout = w_couts[15];
endmodule

module add1 ( input a,
              input b,
              input cin,
             output sum,
             output cout );

    wire [1:0] w_sum;
    assign w_sum = a + b + cin;
    assign {cout,sum}  = w_sum;

endmodule
