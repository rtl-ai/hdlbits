module top_module (
    input [7:0] a, b, c, d,
    output [7:0] min);//

    wire [7:0] w_min_ab;
    wire [7:0] w_min_cd;

    assign w_min_ab = (a < b)               ? a        : b       ;
    assign w_min_cd = (c < d)               ? c        : d       ;
    assign min      = (w_min_ab < w_min_cd) ? w_min_ab : w_min_cd;

endmodule
