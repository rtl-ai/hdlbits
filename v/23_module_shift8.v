module top_module (
    input clk,
    input [7:0] d,
    input [1:0] sel,
    output [7:0] q
);
    wire [7:0] w_q0;
    wire [7:0] w_q1;
    wire [7:0] w_q2;
    reg  [7:0] r_q_final;

    my_dff8 u_my_dff8_0 (.clk(clk), .d(d), .q(w_q0));
    my_dff8 u_my_dff8_1 (.clk(clk), .d(w_q0), .q(w_q1));
    my_dff8 u_my_dff8_2 (.clk(clk), .d(w_q1), .q(w_q2));

    always @(*)
    begin
        case(sel[1:0])
            2'b00:   r_q_final = d;
            2'b01:   r_q_final = w_q0;
            2'b10:   r_q_final = w_q1;
            2'b11:   r_q_final = w_q2;
            default: r_q_final = 8'd0;
        endcase
    end

    assign q = r_q_final;
endmodule

// below part is for only compile, not for HDLBits Site Answers.
module my_dff8(
    input clk,
    input [7:0] d,
    output [7:0] q
);

reg [7:0] r_q;

always @(posedge clk)
begin
    r_q <= d;
end

assign q = r_q;

endmodule