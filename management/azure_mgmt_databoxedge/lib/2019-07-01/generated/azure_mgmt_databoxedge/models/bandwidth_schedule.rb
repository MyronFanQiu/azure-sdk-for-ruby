# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_07_01
  module Models
    #
    # The bandwidth schedule details.
    #
    class BandwidthSchedule < ARMBaseModel

      include MsRestAzure

      # @return [String] The start time of the schedule in UTC.
      attr_accessor :start

      # @return [String] The stop time of the schedule in UTC.
      attr_accessor :stop

      # @return [Integer] The bandwidth rate in Mbps.
      attr_accessor :rate_in_mbps

      # @return [Array<DayOfWeek>] The days of the week when this schedule is
      # applicable.
      attr_accessor :days


      #
      # Mapper for BandwidthSchedule class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'BandwidthSchedule',
          type: {
            name: 'Composite',
            class_name: 'BandwidthSchedule',
            model_properties: {
              id: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'id',
                type: {
                  name: 'String'
                }
              },
              name: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'name',
                type: {
                  name: 'String'
                }
              },
              type: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'type',
                type: {
                  name: 'String'
                }
              },
              start: {
                client_side_validation: true,
                required: true,
                serialized_name: 'properties.start',
                type: {
                  name: 'String'
                }
              },
              stop: {
                client_side_validation: true,
                required: true,
                serialized_name: 'properties.stop',
                type: {
                  name: 'String'
                }
              },
              rate_in_mbps: {
                client_side_validation: true,
                required: true,
                serialized_name: 'properties.rateInMbps',
                type: {
                  name: 'Number'
                }
              },
              days: {
                client_side_validation: true,
                required: true,
                serialized_name: 'properties.days',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'DayOfWeekElementType',
                      type: {
                        name: 'String'
                      }
                  }
                }
              }
            }
          }
        }
      end
    end
  end
end
