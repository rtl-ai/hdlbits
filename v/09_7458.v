module top_module ( 
    input p1a, p1b, p1c, p1d, p1e, p1f,
    output p1y,
    input p2a, p2b, p2c, p2d,
    output p2y );

wire w_p1a_and_p1b_and_p1c;
wire w_p1d_and_p1e_and_p1f;

wire w_p2a_and_p2b;
wire w_p2c_and_p2d;
wire w_aandb_or_candd;

assign w_p1a_and_p1b_and_p1c = p1a & p1b & p1c;
assign w_p1d_and_p1e_and_p1f = p1d & p1e & p1f;
assign p1y                   = w_p1a_and_p1b_and_p1c | w_p1d_and_p1e_and_p1f;

assign w_p2a_and_p2b    = p2a & p2b;
assign w_p2c_and_p2d    = p2c & p2d;
assign p2y              = w_p2a_and_p2b | w_p2c_and_p2d;

endmodule
