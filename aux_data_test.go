package deposit_address

import (
	"encoding/hex"
	"math"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeAuxDataV0(t *testing.T) {
	referalData, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)

	type args struct {
		nonce      uint32
		referrerId []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "successful with max uint32",
			args: args{
				nonce:      math.MaxUint32,
				referrerId: referalData,
			},
			want: "57302e91d7d3252be7c273a0041848c13c00b6d0782fef778f2ecab26fb0c0f8",
		},
		{
			name: "successful with max uint32 - 1",
			args: args{
				nonce:      math.MaxUint32 - 1,
				referrerId: referalData,
			},
			want: "ad4abce054b9882828ac0c8003164660fd8ffc6e7005180e3e182770d4ae02c0",
		},
		{
			name: "successful with 0",
			args: args{
				nonce:      0,
				referrerId: referalData,
			},
			want: "2137aefeb756a435f07fceff39a061bd2a062b617bd8857e9c32b44ef2596bc8",
		},
		{
			name: "successful with 1",
			args: args{
				nonce:      1,
				referrerId: referalData,
			},
			want: "58bd0e282e046b08c0d395ea701678a1161f8f46362abc4a25b37dce12e57fcf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComputeAuxDataV0(tt.args.nonce, tt.args.referrerId)
			require.NoError(t, err)
			if !reflect.DeepEqual(hex.EncodeToString(got), tt.want) {
				t.Errorf("ComputeAuxDataV0() = %x, want %v", got, tt.want)
			}
		})
	}
}

func TestComputeAuxDataV1(t *testing.T) {
	referalData, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)

	type args struct {
		nonce      uint32
		referrerId []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "successful with max uint32",
			args: args{
				nonce:      math.MaxUint32,
				referrerId: referalData,
			},
			want: "57aedd1ef8765c190f826be6d0c54add6490bb0df5b783c151989d66c8b2b12c",
		},
		{
			name: "successful with max uint32 - 1",
			args: args{
				nonce:      math.MaxUint32 - 1,
				referrerId: referalData,
			},
			want: "46b7319fd3fd314c5f9a1fb4ed81f1f19f3ea06173827bd6ec2f8653d23bed9d",
		},
		{
			name: "successful with 0",
			args: args{
				nonce:      0,
				referrerId: referalData,
			},
			want: "7eb52f8f0d25a9fd2d7d810ded653ac10c41cbc21696ad073076b8a7d389025a",
		},
		{
			name: "successful with 1",
			args: args{
				nonce:      1,
				referrerId: referalData,
			},
			want: "a84442c7706a991e0d45027cf3926385efe3f7b95b19a8b316bdbc1c73fb79b2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComputeAuxDataV1(tt.args.nonce, tt.args.referrerId)
			require.NoError(t, err)
			if !reflect.DeepEqual(hex.EncodeToString(got), tt.want) {
				t.Errorf("ComputeAuxDataV1() = %x, want %v", got, tt.want)
			}
		})
	}
}
