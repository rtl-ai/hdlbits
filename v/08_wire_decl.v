`default_nettype none
module top_module(
    input a,
    input b,
    input c,
    input d,
    output out,
    output out_n   ); 

wire w_and_ab;
wire w_and_cd;
wire w_or_abcd;

assign w_and_ab  =  a & b;
assign w_and_cd  =  c & d;
assign w_or_abcd =  w_and_ab | w_and_cd;
assign out       =  w_or_abcd;
assign out_n     = ~w_or_abcd;

endmodule
