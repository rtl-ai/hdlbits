module top_module (
    input  [254:0] in,
    output [  7:0] out
);

  wire [1:0] w_sum_lv0[0:127];
  genvar i0;
  generate
    for (i0 = 0; i0 < 127; i0 = i0 + 1) begin : g_lv0
      assign w_sum_lv0[i0] = {1'b0, in[2*i0]} + {1'b0, in[2*i0+1]};
    end
  endgenerate
  assign w_sum_lv0[127] = {1'b0, in[254]};

  wire [2:0] w_sum_lv1[0:63];
  genvar i1;
  generate
    for (i1 = 0; i1 < 64; i1 = i1 + 1) begin : g_lv1
      assign w_sum_lv1[i1] = {1'b0, w_sum_lv0[2*i1]} + {1'b0, w_sum_lv0[2*i1+1]};
    end
  endgenerate

  wire [3:0] w_sum_lv2[0:31];
  genvar i2;
  generate
    for (i2 = 0; i2 < 32; i2 = i2 + 1) begin : g_lv2
      assign w_sum_lv2[i2] = {1'b0, w_sum_lv1[2*i2]} + {1'b0, w_sum_lv1[2*i2+1]};
    end
  endgenerate

  wire [4:0] w_sum_lv3[0:15];
  genvar i3;
  generate
    for (i3 = 0; i3 < 16; i3 = i3 + 1) begin : g_lv3
      assign w_sum_lv3[i3] = {1'b0, w_sum_lv2[2*i3]} + {1'b0, w_sum_lv2[2*i3+1]};
    end
  endgenerate

  wire [5:0] w_sum_lv4[0:7];
  genvar i4;
  generate
    for (i4 = 0; i4 < 8; i4 = i4 + 1) begin : g_lv4
      assign w_sum_lv4[i4] = {1'b0, w_sum_lv3[2*i4]} + {1'b0, w_sum_lv3[2*i4+1]};
    end
  endgenerate

  wire [6:0] w_sum_lv5[0:3];
  genvar i5;
  generate
    for (i5 = 0; i5 < 4; i5 = i5 + 1) begin : g_lv5
      assign w_sum_lv5[i5] = {1'b0, w_sum_lv4[2*i5]} + {1'b0, w_sum_lv4[2*i5+1]};
    end
  endgenerate

  wire [7:0] w_sum_lv6[0:1];
  assign w_sum_lv6[0] = {1'b0, w_sum_lv5[0]} + {1'b0, w_sum_lv5[1]};
  assign w_sum_lv6[1] = {1'b0, w_sum_lv5[2]} + {1'b0, w_sum_lv5[3]};

  assign out = w_sum_lv6[0] + w_sum_lv6[1];

endmodule
