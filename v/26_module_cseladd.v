module top_module(
    input [31:0] a,
    input [31:0] b,
    output [31:0] sum
);
wire [15:0] w_msb_a;
wire [15:0] w_lsb_a;
wire [15:0] w_msb_b;
wire [15:0] w_lsb_b;
wire [15:0] w_sum_lsb;
wire [15:0] w_sum_msb_carry1;
wire [15:0] w_sum_msb_carry0;
wire w_cout_msb_carry1;
wire w_cout_msb_carry0;
wire w_cout_lsb;

wire [31:0] w_sum_msb_selected;

assign {w_msb_a, w_lsb_a} = a;
assign {w_msb_b, w_lsb_b} = b;

add16 u_add16_msb_carry1 (
.a(w_msb_a),
.b(w_msb_b),
.cin(1'b1),
.sum(w_sum_msb_carry1),
.cout(w_cout_msb_carry1)
);

add16 u_add16_msb_carry0 (
.a(w_msb_a),
.b(w_msb_b),
.cin(1'b0),
.sum(w_sum_msb_carry0),
.cout(w_cout_msb_carry0)
);

add16 u_add16_lsb (
.a(w_lsb_a),
.b(w_lsb_b),
.cin(1'b0),
.sum(w_sum_lsb),
.cout(w_cout_lsb)
);

assign w_sum_msb_selected = w_cout_lsb ? w_sum_msb_carry1 : w_sum_msb_carry0;
assign sum = {w_sum_msb_selected, w_sum_lsb};

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