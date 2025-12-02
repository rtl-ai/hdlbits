//18_vector5.v
module top_module (
    input a, b, c, d, e,
    output [24:0] out );//

    // The output is XNOR of two vectors created by 
    // concatenating and replicating the five inputs.
    // assign out = ~{ ... } ^ { ... };

wire [24:0] w_abcde;
assign w_abcde = {5{a,b,c,d,e}};

assign out[24:20] = ~ ( (w_abcde[24:20]) ^{5{a}});
assign out[19:15] = ~ ( (w_abcde[19:15]) ^{5{b}});
assign out[14:10] = ~ ( (w_abcde[14:10]) ^{5{c}});
assign out[9:5] = ~ ( (w_abcde[9:5]) ^{5{d}});
assign out[4:0] = ~ ( (w_abcde[4:0]) ^{5{e}});

endmodule
