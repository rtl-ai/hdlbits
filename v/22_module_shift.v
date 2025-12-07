module top_module ( input clk, input d, output q );


    wire w_dff_q0;
    wire w_dff_q1;
    wire w_dff_q2;

    my_dff u_my_dff_0 (.clk(clk), .d(d)       , .q(w_dff_q0));
    my_dff u_my_dff_1 (.clk(clk), .d(w_dff_q0), .q(w_dff_q1));
    my_dff u_my_dff_2 (.clk(clk), .d(w_dff_q1), .q(w_dff_q2));

assign q = w_dff_q2;

endmodule

module my_dff(
    input clk,
    input d,
    output reg q
);

always @(posedge clk)
begin
    q <= d;
end

endmodule